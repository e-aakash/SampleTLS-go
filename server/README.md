Create new certificate and private key (taken from https://stackoverflow.com/a/63590299)

```
openssl ecparam -genkey -name secp384r1 -out server.key
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

Start the server:

```
go run server.go
```
