package main

type AlertLevel uint8

const (
	WarningAlert AlertLevel = 1
	FatalAlert   AlertLevel = 2
)

type AlertDescription uint8

const (
	Close_notify                AlertDescription = 0
	Unexpected_message          AlertDescription = 10
	Bad_record_mac              AlertDescription = 20
	Decryption_failed_RESERVED  AlertDescription = 21
	Record_overflow             AlertDescription = 22
	Decompression_failure       AlertDescription = 30
	Handshake_failure           AlertDescription = 40
	No_certificate_RESERVED     AlertDescription = 41
	Bad_certificate             AlertDescription = 42
	Unsupported_certificate     AlertDescription = 43
	Certificate_revoked         AlertDescription = 44
	Certificate_expired         AlertDescription = 45
	Certificate_unknown         AlertDescription = 46
	Illegal_parameter           AlertDescription = 47
	Unknown_ca                  AlertDescription = 48
	Access_denied               AlertDescription = 49
	Decode_error                AlertDescription = 50
	Decrypt_error               AlertDescription = 51
	Export_restriction_RESERVED AlertDescription = 60
	Protocol_version            AlertDescription = 70
	Insufficient_security       AlertDescription = 71
	Internal_error              AlertDescription = 80
	User_canceled               AlertDescription = 90
	No_renegotiation            AlertDescription = 100
	Unsupported_extension       AlertDescription = 110
)

type Alert struct {
	level       AlertLevel
	description AlertDescription
}
