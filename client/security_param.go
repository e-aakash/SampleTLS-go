package main

type CompressionMethod uint8

const (
	NullCompression    CompressionMethod = 0
	DeflateCompression CompressionMethod = 1
)

type ConnectionEnd uint8

const (
	Server ConnectionEnd = 0
	Client ConnectionEnd = 1
)

type PRFAlgo uint8

const (
	TLS_PRF_SHA256 PRFAlgo = 0
)

type BulkCipherAlgo uint8

const (
	NullCipher BulkCipherAlgo = 0
	RC4Cipher  BulkCipherAlgo = 1
	DES3Cihper BulkCipherAlgo = 2
	AESCipher  BulkCipherAlgo = 3
)

type CipherType uint8

const (
	StreamCipher CipherType = 0
	BlockCipher  CipherType = 1
	AEADCipher   CipherType = 2
)

type MACAlgo uint8

const (
	NullMac     MACAlgo = 0
	HMAC_MD5    MACAlgo = 1
	HMAC_SHA1   MACAlgo = 2
	HMAC_SHA256 MACAlgo = 3
	HMAC_SHA384 MACAlgo = 4
	HMAC_SHA512 MACAlgo = 5
)

type SecurityParams struct {
	entity             ConnectionEnd
	prf_algo           PRFAlgo
	bulk_cipher_algo   BulkCipherAlgo
	cipher_type        CipherType
	enc_key_length     uint8
	block_length       uint8
	fixed_iv_length    uint8
	record_iv_length   uint8
	mac_algo           MACAlgo
	mac_length         uint8
	mac_key_length     uint8
	compression_method CompressionMethod
	master_secret      [48]byte
	client_random      [32]byte
	server_random      [32]byte
}

type TLSSecurityKeys struct {
	client_write_MAC_key []byte
	server_write_MAC_key []byte
	client_write_key     []byte
	server_write_key     []byte
	// This is needed only in AEAD
	client_write_iv []byte
	server_write_iv []byte
}

type CipherSuite uint16

const (
	TLS_NULL_WITH_NULL_NULL             CipherSuite = 0x00
	TLS_RSA_WITH_NULL_MD5               CipherSuite = 0x01
	TLS_RSA_WITH_NULL_SHA               CipherSuite = 0x02
	TLS_RSA_WITH_NULL_SHA256            CipherSuite = 0x3B
	TLS_RSA_WITH_RC4_128_MD5            CipherSuite = 0x04
	TLS_RSA_WITH_AES_256_CBC_SHA256     CipherSuite = 0x3D
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA    CipherSuite = 0x0D
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA    CipherSuite = 0x10
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA   CipherSuite = 0x13
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   CipherSuite = 0x16
	TLS_DH_DSS_WITH_AES_128_CBC_SHA     CipherSuite = 0x30
	TLS_DH_RSA_WITH_AES_128_CBC_SHA     CipherSuite = 0x31
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA    CipherSuite = 0x32
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA    CipherSuite = 0x33
	TLS_DH_DSS_WITH_AES_256_CBC_SHA     CipherSuite = 0x36
	TLS_DH_RSA_WITH_AES_256_CBC_SHA     CipherSuite = 0x37
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA    CipherSuite = 0x38
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA    CipherSuite = 0x39
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256  CipherSuite = 0x3E
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256  CipherSuite = 0x3F
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 CipherSuite = 0x40
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 CipherSuite = 0x67
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256  CipherSuite = 0x68
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256  CipherSuite = 0x69
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 CipherSuite = 0x6A
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 CipherSuite = 0x6B

	// Constants from https://pkg.go.dev/crypto/tls#pkg-constants
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA                      CipherSuite = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 CipherSuite = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA                  CipherSuite = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA                  CipherSuite = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256               CipherSuite = 0x003c
	TLS_RSA_WITH_AES_128_GCM_SHA256               CipherSuite = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384               CipherSuite = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              CipherSuite = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          CipherSuite = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          CipherSuite = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                CipherSuite = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           CipherSuite = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            CipherSuite = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            CipherSuite = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       CipherSuite = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         CipherSuite = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         CipherSuite = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       CipherSuite = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         CipherSuite = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   CipherSuite = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca9

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384       CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 CipherSuite = 0x1303
)
