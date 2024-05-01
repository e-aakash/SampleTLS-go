# TLS sample implementation

To understand how HTTPS / TLS works, i am trying to implement client part of TLS protocol. For the server part, i am using self signed cert backed https server from "net/http" go package.

Currently ClientHello is correctly implemented, which itself is failing due to not sending enough cipher suites which go server supports out of the box.

While testing with own server is not working, sending client hello against `www.insti.app:443` is resulting in ServerHello and ServerCert being sent back
