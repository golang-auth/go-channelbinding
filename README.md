## go-channelbinding: Go library to create TLS channel binding data for use with authentcation protocols

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/golang-auth/go-channelbinding)
[![Git Workflow](https://img.shields.io/github/workflow/status/golang-auth/go-channelbinding/unit-tests)](https://img.shields.io/github/workflow/status/golang-auth/go-channelbinding/unit-tests)
[![Go Version](https://img.shields.io/badge/go%20version-%3E=1.13-61CFDD.svg?style=flat-square)](https://golang.org/)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/golang-auth/go-channelbinding/v2)](https://pkg.go.dev/mod/github.com/golang-auth/go-channelbinding)

go-channelbinding provides TLS Channel Binding support as defined
in [RFC 5929](https://tools.ietf.org/html/rfc5929):

   * tls-unique: binds to an individual TLS connection
   * tls-endpoint: binds to the server's TLS certificate

These bindings are available for TLS versions prior to TLS1.3 only, and
are subject to issues related to session resumption and renegotiation,
as described in this [miTLS paper](https://mitls.org/pages/attacks/3SHAKE#channelbindings).
Please take time to read and understand the limitations before relying on
channel bindings to secure authentication protocols.

## Example
```go
package main

import (
	"crypto/tls"
	"fmt"
	"os"

	cb "github.com/golang-auth/go-channelbinding"
)

func main() {
	tlsConf := tls.Config{MaxVersion: tls.VersionTLS12}

	conn, err := tls.Dial("tcp", "ldap.example.com:636", &tlsConf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tlsState := conn.ConnectionState()
	data, err := cb.MakeTLSChannelBinding(tlsState, tlsState.PeerCertificates[0], cb.TLSChannelBindingEndpoint)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// use data...
	_ = data
}
```

## TLS 1.3

TLS 1.3 does not define the tls-unqiue and tls-endpoint bindings due to the security concerns outlined in the
referenced miTLS paper.  A [draft proposal](https://tools.ietf.org/id/draft-ietf-kitten-tls-channel-bindings-for-tls13-00.html) has been created to close that gap, and that is
experimentially supported by the `TLSChannelBindingExporter` binding type.  Note however that at this time
the author knows of no test vectors or other implemtations.