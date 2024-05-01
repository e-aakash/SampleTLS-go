package main

import (
	"bytes"
	"context"
	"crypto/rand"
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

	buf := testTLSPlainText()
	fmt.Printf("Bytes: [% x]\n", buf)

	if _, err := conn.Write(buf); err != nil {
		log.Fatal(err)
	}

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
}

func main() {
	// testTLSPlainText()
	Dialer()
}

func testTLSPlainText() []byte {
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
		cipher_suites_length:      4,
		cipher_suites:             []CipherSuite{TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256},
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
		version:     TLS1_1,
		length:      uint16(len(handshake_bytes)),
		fragment:    handshake_bytes,
	}

	buf := new(bytes.Buffer)
	_ = plaintext.GetBytes(buf)
	return buf.Bytes()
}
