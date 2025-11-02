// SPDX-License-Identifier: Apache-2.0

/*
Package channelbinding provides TLS Channel Binding support as defined
in RFC 5929:

	tls-unique:           binds to an individual TLS connection
	tls-server-end-point: binds to the server's TLS certificate

These bindings are available for TLS versions prior to TLS1.3 only, and
are subject to issues related to session resumption and renegotiation,
as described in the [miTLS paper].
Please take time to read and understand the limitations before relying on
channel bindings to secure authentication protocols.

The library also supports channel bindings for TLS 1.3 as defined
in RFC 9266:

	tls-exporter: binds to TLS Exported Keying Material (EKM)

[miTLS paper]: https://github.com/golang-auth/go-channelbinding/blob/main/doc/miTLS-Triple-Handshake-SMACK-FREAK-Logjam-SLOTH.md
*/
package channelbinding
