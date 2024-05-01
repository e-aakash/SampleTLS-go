package main

import (
    "log"
    "net/http"
)

func SecureServer(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("Secure Hello World.\n"))
}

func main() {
    http.HandleFunc("/secure", SecureServer)
    err := http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil)
    if err != nil {
            log.Fatal("ListenAndServe: ", err)
    }
}
