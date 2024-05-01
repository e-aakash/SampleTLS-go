package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type HandshakeType uint8

const (
	Hello_request       HandshakeType = 0
	Client_hello        HandshakeType = 1
	Server_hello        HandshakeType = 2
	Certificate         HandshakeType = 11
	Server_key_exchange HandshakeType = 12
	Certificate_request HandshakeType = 13
	Server_hello_done   HandshakeType = 14
	Certificate_verify  HandshakeType = 15
	Client_key_exchange HandshakeType = 16
	Finished            HandshakeType = 20
)

type Handshake struct {
	handshakeType HandshakeType
	length        uint32 // this is 24 bytes only
	body          []byte
}

func (handshake *Handshake) Bytes() []byte {
	var mask uint32
	mask = 0b11111111
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, handshake.handshakeType)
	// binary.Write(buf, binary.BigEndian, (handshake.length))
	// fmt.Printf("% b\n", handshake.length)
	// fmt.Printf("first part: %b\n", uint8((handshake.length>>16)&mask))
	// fmt.Printf("first part: %b\n", uint8((handshake.length>>8)&mask))
	// fmt.Printf("first part: %b\n", uint8((handshake.length)&mask))
	// fmt.Println("length: ", handshake.length)
	binary.Write(buf, binary.BigEndian, uint8((handshake.length>>16)&mask))
	binary.Write(buf, binary.BigEndian, uint8((handshake.length>>8)&mask))
	binary.Write(buf, binary.BigEndian, uint8((handshake.length)&mask))
	// fmt.Printf("Bytes: [% x]\n", buf)
	binary.Write(buf, binary.BigEndian, handshake.body)
	return buf.Bytes()
}

type HandshakeRandom struct {
	gmt_unix_timestamp uint32
	random_bytes       [28]byte
}

type ClientHello struct {
	client_version            ProtocolVersion
	random                    HandshakeRandom
	session_id_length         uint8
	session_id                []byte
	cipher_suites_length      uint16 // this is length of next array data in bytes, not length of the array. TODO: Abstract this away?
	cipher_suites             []CipherSuite
	compression_method_length uint8
	compression_method        []CompressionMethod
	// TODO: Add extensions?
}

func (hello *ClientHello) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, hello.client_version.major)
	binary.Write(buf, binary.BigEndian, hello.client_version.minor)
	binary.Write(buf, binary.BigEndian, hello.random.gmt_unix_timestamp)
	binary.Write(buf, binary.BigEndian, hello.random.random_bytes)

	// if hello.session_id_length > 0 {
	binary.Write(buf, binary.BigEndian, hello.session_id_length)
	binary.Write(buf, binary.BigEndian, hello.session_id)
	// }
	binary.Write(buf, binary.BigEndian, hello.cipher_suites_length)
	for _, suite := range hello.cipher_suites {
		binary.Write(buf, binary.BigEndian, suite)
	}
	binary.Write(buf, binary.BigEndian, hello.compression_method_length)
	binary.Write(buf, binary.BigEndian, hello.compression_method)

	return buf.Bytes()
}

type ServerHello struct {
	server_version     ProtocolVersion
	random             HandshakeRandom
	session_id_length  uint8
	session_id         []byte
	cipher_suite       CipherSuite
	compression_method CompressionMethod
}

func (shello *ServerHello) FromReader(reader io.Reader) error {
	binary.Read(reader, binary.BigEndian, &shello.server_version.major)
	binary.Read(reader, binary.BigEndian, &shello.server_version.minor)

	binary.Read(reader, binary.BigEndian, &shello.random.gmt_unix_timestamp)
	binary.Read(reader, binary.BigEndian, &shello.random.random_bytes)

	binary.Read(reader, binary.BigEndian, &shello.session_id_length)
	shello.session_id = make([]byte, shello.session_id_length)
	binary.Read(reader, binary.BigEndian, &shello.session_id)

	binary.Read(reader, binary.BigEndian, &shello.cipher_suite)
	binary.Read(reader, binary.BigEndian, &shello.compression_method)

	return nil
}

// HACK! HACK! HACK! This message is wrapped by types/TLSPlainText.
// Skipping checking those params for now
// TODO: Think of cleanly handling nested structure reading?
func SHelloHandshakeFromConn(conn *net.Conn) (hello *ServerHello, err error) {
	var skippedBytes [5]uint8
	binary.Read(*conn, binary.BigEndian, &skippedBytes)
	var rawValue uint8
	binary.Read(*conn, binary.BigEndian, &rawValue)

	fmt.Println("handshake type: ", rawValue)
	if HandshakeType(rawValue) != (Server_hello) {
		// handle error, terminate connection
		fmt.Println("Invalid response from server")
	}

	var payloadLengthBytes [3]uint8 // only 28 bytes is sent as length
	binary.Read(*conn, binary.BigEndian, &payloadLengthBytes)

	var payloadLength uint32 = ((uint32)(payloadLengthBytes[0]))<<16 + ((uint32)(payloadLengthBytes[1]))<<8 + ((uint32)(payloadLengthBytes[2]))
	data := make([]byte, payloadLength)
	binary.Read(*conn, binary.BigEndian, data)

	serverHello := ServerHello{}
	r := bytes.NewReader(data)
	serverHello.FromReader(r)
	fmt.Println("ServerHello: ", serverHello)

	return &serverHello, nil
}
