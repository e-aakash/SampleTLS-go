package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

var TLS1_1 ProtocolVersion = ProtocolVersion{3, 1}
var TLS1_2 ProtocolVersion = ProtocolVersion{3, 3}

func createClientHello() *ClientHello {
	return nil
}

func Dialer() {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", "www.insti.app:443")
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	fmt.Println(`Conned`)
	defer conn.Close()

	chello, _, buf := testTLSPlainText()
	fmt.Printf("Bytes: [% x]\n", buf)

	if _, err := conn.Write(buf); err != nil {
		log.Fatal(err)
	}

	// TODO: Think of a better way of handling the state machine/sequence?

	var shello *ServerHello
	if shello, err = SHelloHandshakeFromConn(&conn); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("% x \n", shello.random.random_bytes)

	// Assuming connection always requires server cert
	var scert *ServerCertificate
	if scert, err = SCertHandshakeFromConn(&conn); err != nil {
		log.Fatal(err)
	}
	fmt.Println(scert.certificate_list[0].cert.Subject)

	// TODO: Implement server key exchange message parsing if selected algo requires it

	// Server Hello done
	if err = SHelloDoneHandshakeFromConn(&conn); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Server hello done")

	// Validate params so far and cert from server

	// Send client key exchange
	pms := PreMasterSecret{
		client_version: TLS1_2, // get this from client hello, as per spec
	}
	rand.Read(pms.random[:])

	cke, _ := pms.CreateMessage(scert)
	var cke_bytes = cke.Bytes()
	var handshake = Handshake{
		handshakeType: Client_key_exchange,
		length:        uint32(len(cke_bytes)),
		body:          cke_bytes,
	}
	handshake_bytes := handshake.Bytes()
	var plaintext = TLSPlainText{
		contentType: Handshake_type,
		version:     TLS1_2,
		length:      uint16(len(handshake_bytes)),
		fragment:    handshake_bytes,
	}

	// TODO: Move this to func in all tls message types?
	bytes_buffer := new(bytes.Buffer)
	_ = plaintext.GetBytes(bytes_buffer)
	buf = bytes_buffer.Bytes()

	if _, err := conn.Write(buf); err != nil {
		log.Fatal(err)
	}

	// Change cipher spec
	ccs := ChangeCihperSpecMesasge{}
	ccs_bytes := ccs.Bytes()
	plaintext = TLSPlainText{
		contentType: Change_cipher_spec_type,
		version:     TLS1_2,
		length:      uint16(len(ccs_bytes)),
		fragment:    ccs_bytes,
	}
	bytes_buffer.Reset()
	_ = plaintext.GetBytes(bytes_buffer)
	buf = bytes_buffer.Bytes()

	if _, err := conn.Write(buf); err != nil {
		log.Fatal(err)
	}

	// Compute master secret
	var master_secret [48]byte
	byte_buffer := new(bytes.Buffer)
	binary.Write(byte_buffer, binary.BigEndian, chello.random.gmt_unix_timestamp)
	binary.Write(byte_buffer, binary.BigEndian, chello.random.random_bytes)
	client_random := byte_buffer.Bytes()
	byte_buffer.Reset()
	binary.Write(byte_buffer, binary.BigEndian, shello.random.gmt_unix_timestamp)
	binary.Write(byte_buffer, binary.BigEndian, shello.random.random_bytes)
	server_random := byte_buffer.Bytes()
	combined_radom := append(client_random, server_random...)
	secret := PRF(pms.Bytes(), "master secret", combined_radom, 48)
	master_secret = [48]byte(secret[:48])

	// Currently handcoding based on only cipher suite present in this client
	securityParams := SecurityParams{
		entity:             Client,
		prf_algo:           TLS_PRF_SHA256,
		bulk_cipher_algo:   AESCipher,
		cipher_type:        BlockCipher,
		mac_algo:           HMAC_SHA256,
		block_length:       16,
		enc_key_length:     16,
		fixed_iv_length:    16,
		record_iv_length:   16,
		mac_length:         32,
		mac_key_length:     32,
		compression_method: NullCompression,
		master_secret:      master_secret,
		client_random:      [32]byte(client_random),
		server_random:      [32]byte(server_random),
	}

	// Currently only for single cipher suite we are hardcoding. AEAD requires IV also!
	random_values_length := 2*securityParams.mac_key_length + 2*securityParams.enc_key_length
	random_values_from_master_key := PRF(securityParams.master_secret[:], "key expansion", combined_radom, int(random_values_length))

	tls_security_keys := TLSSecurityKeys{}
	base := uint8(0)
	tls_security_keys.client_write_MAC_key = random_values_from_master_key[base : base+securityParams.mac_key_length]
	base += (securityParams.mac_key_length)
	tls_security_keys.server_write_MAC_key = random_values_from_master_key[base : base+securityParams.mac_key_length]
	base += (securityParams.mac_key_length)
	tls_security_keys.client_write_key = random_values_from_master_key[base : base+securityParams.enc_key_length]
	base += (securityParams.enc_key_length)
	tls_security_keys.server_write_key = random_values_from_master_key[base : base+securityParams.enc_key_length]

	// Client FIN
	cfin := ClientFinished{
		verify_data_length: [3]byte{0x00, 0x00, 0x0c},
		verify_data:        [12]byte{0x0},
	}
	cfin_bytes := cfin.Bytes()
	handshake = Handshake{
		handshakeType: Finished,
		length:        uint32(len(cfin_bytes)),
		body:          cfin_bytes,
	}
	handshake_bytes = handshake.Bytes()
	plaintext = TLSPlainText{
		contentType: Handshake_type,
		version:     TLS1_2,
		length:      uint16(len(handshake_bytes)),
		fragment:    handshake_bytes,
	}
	bytes_buffer.Reset()
	_ = plaintext.GetBytes(bytes_buffer)
	buf = bytes_buffer.Bytes()

	if _, err := conn.Write(buf); err != nil {
		log.Fatal(err)
	}
	// for now close the connection to ensure server conn is cleaned up
	conn.Close()
}

func main() {
	// testTLSPlainText()
	Dialer()
}

func testTLSPlainText() (ClientHello, Handshake, []byte) {
	var random_bytes [28]byte
	rand.Read(random_bytes[:])
	var random = HandshakeRandom{
		gmt_unix_timestamp: uint32(time.Now().UnixMilli() / 1000.0),
		random_bytes:       random_bytes,
	}
	var clientHello = ClientHello{
		client_version:            TLS1_2,
		random:                    random,
		session_id_length:         0,
		session_id:                []byte{},
		cipher_suites_length:      2,
		cipher_suites:             []CipherSuite{TLS_RSA_WITH_AES_128_CBC_SHA256},
		compression_method_length: 1,
		compression_method:        []CompressionMethod{NullCompression},
	}
	frag := clientHello.Bytes()
	var handshake = Handshake{
		handshakeType: Client_hello,
		length:        uint32(len(frag)),
		body:          frag,
	}
	handshake_bytes := handshake.Bytes()
	var plaintext = TLSPlainText{
		contentType: Handshake_type,
		version:     TLS1_2,
		length:      uint16(len(handshake_bytes)),
		fragment:    handshake_bytes,
	}

	buf := new(bytes.Buffer)
	_ = plaintext.GetBytes(buf)
	return clientHello, handshake, buf.Bytes()
}

func PRF(secret []byte, label string, seed []byte, len int) []byte {
	// sha 256 is the only PRF hash supported in tls 1.2
	bytes_generated := 0
	hash_seed := []byte(label)
	hash_seed = append(hash_seed, seed...)

	// p_hash: seed -> hash_seed
	random := make([]byte, 0)
	hmac_hash := hmac.New(sha256.New, secret)
	inner_seed := hmac_hash.Sum(hash_seed) // A1

	for {
		if bytes_generated > len {
			break
		}

		outer_hash := hmac_hash.Sum(append(inner_seed, hash_seed...))
		random = append(random, outer_hash...)
		inner_seed = hmac_hash.Sum(inner_seed)
		bytes_generated += 32
	}
	return random[:len]
}
