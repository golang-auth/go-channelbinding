// SPDX-License-Identifier: Apache-2.0

/*
Package channelbinding provides TLS Channel Binding support as defined
in RFC 5929:

	tls-unique:           binds to an individual TLS connection
	tls-server-end-point: binds to the server's TLS certificate

These bindings are available for TLS versions prior to TLS1.3 only, and
are subject to issues related to session resumption and renegotiation,
as described in https://mitls.org/pages/attacks/3SHAKE#channelbindings.
Please take time to read and understand the limitations before relying on
channel bindings to secure authentication protocols.
*/
package channelbinding
