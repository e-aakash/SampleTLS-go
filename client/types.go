package main

import (
	"bytes"
	"encoding/binary"
)

type ContentType int8

const (
	Change_cipher_spec_type ContentType = 20
	Alert_type              ContentType = 21
	Handshake_type          ContentType = 22
	Application_data_type   ContentType = 23
)

type ProtocolVersion struct {
	major uint8
	minor uint8
}

type TLSPlainText struct {
	contentType ContentType
	version     ProtocolVersion
	length      uint16 // Must not be > 2^14
	fragment    []byte
}

func (tlsPlainText *TLSPlainText) GetBytes(buf *bytes.Buffer) error {
	err := binary.Write(buf, binary.BigEndian, tlsPlainText.contentType)
	err = binary.Write(buf, binary.BigEndian, tlsPlainText.version.major)
	err = binary.Write(buf, binary.BigEndian, tlsPlainText.version.minor)
	err = binary.Write(buf, binary.BigEndian, tlsPlainText.length)
	err = binary.Write(buf, binary.BigEndian, tlsPlainText.fragment)

	return err
}

type TLSCompressed struct {
	contentType ContentType
	version     ProtocolVersion
	length      uint16 // Must not be > 2^14 + 1024
	fragment    []byte
}

type AEADCipherContent struct {
	nonce             []byte
	ciphered_fragment []byte
}

type StreamCipherContent struct {
	content []byte
	mac     []byte
}

type BlockCipherContent struct {
	iv          []byte
	content     []byte
	mac         []byte
	padding     []uint8
	padding_len uint8
}

type TLSCipherText struct {
	contentType ContentType
	version     ProtocolVersion
	length      uint16 // Must not be > 2^14 + 2048
	fragment    BlockCipherContent
}
