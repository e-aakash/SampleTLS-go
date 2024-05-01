package main

import (
	"bytes"
	"encoding/binary"
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

type ClientHelloRandom struct {
	gmt_unix_timestamp uint32
	random_bytes       [28]byte
}

type ClientHello struct {
	client_version            ProtocolVersion
	random                    ClientHelloRandom
	session_id_length         uint8
	session_id                []byte
	cipher_suites_length      uint16
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
