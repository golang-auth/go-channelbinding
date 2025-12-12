## go-channelbinding: Go library to create TLS channel binding data for use with authentcation protocols

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/golang-auth/go-channelbinding)
[![Git Workflow](https://img.shields.io/github/actions/workflow/status/golang-auth/go-channelbinding/checks.yml)](https://img.shields.io/github/actions/workflow/status/golang-auth/go-channelbinding/checks.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/golang-auth/go-channelbinding?style=flat-square)](https://goreportcard.com/report/github.com/golang-auth/go-channelbinding)
[![Go Version](https://img.shields.io/badge/go%20version-%3E=1.13-61CFDD.svg?style=flat-square)](https://golang.org/)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/golang-auth/go-channelbinding/v2)](https://pkg.go.dev/mod/github.com/golang-auth/go-channelbinding)
[![GitHub](https://img.shields.io/github/license/golang-auth/go-channelbinding)](https://raw.githubusercontent.com/golang-auth/go-channelbinding/main/LICENSE)


go-channelbinding provides TLS Channel Binding support as defined
in [RFC 5929][RFC5929]:

   * tls-unique:           binds to an individual TLS connection
   * tls-server-end-point: binds to the server's TLS certificate

These bindings are available for TLS versions prior to TLS1.3 only, and
are subject to issues related to session resumption and renegotiation,
as described in this [miTLS paper][miTLS paper].
Please take time to read and understand the limitations before relying on
channel bindings to secure authentication protocols.

The library also supports channel bindings for TLS 1.3 as defined
in [RFC 9266][RFC9266]:

   * tls-exporter: binds to TLS Exported Keying Material (EKM)


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

The tls-server-endpoint and tls-exporter bindings are supported for TLS 1.3, with
tls-exporter repacing tls-unique that was available for earlier TLS versions.  tls-unique
is not available for TLS 1.3 (see the security concerns outlined in the
referenced miTLS paper).   As mentioned in [RFC 9266][RFC9266],
tls-exporter should only be used when extended master secrets are in use.  Go 1.22 and later disables the use
of exported key material when extended master secrets or TLS 1.3 are not in use so attempting to use this module
in those cases will fail safe.


[RFC5929]: https://tools.ietf.org/html/rfc5929
[RFC9266]: https://datatracker.ietf.org/doc/html/rfc9266#name-use-with-legacy-tls
[miTLS paper]: ./doc/miTLS-Triple-Handshake-SMACK-FREAK-Logjam-SLOTH.md
