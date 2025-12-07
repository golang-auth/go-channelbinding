// SPDX-License-Identifier: Apache-2.0

package channelbinding

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// TLSChannelBindingType defines a TLS Channel Binding type
type TLSChannelBindingType int

// Supported TLS channel binding types
const (
	TLSChannelBindingNone = iota
	TLSChannelBindingUnique
	TLSChannelBindingEndpoint
	TLSChannelBindingExporter
)

// MakeTLSChannelBinding creates the TLS channel binding data for a given binding type.
//
// Unfortunately it is not possible to determine whether the caller is the client or
// server from the ConncetionState alone.  Therefore, serverCert must be passed when
// requesting TLSCHannelBindingEndpoint binding.  For a client, this value is
// state.PeerCertificates[0].  Determining which certificate to use for a server is more
// complex when multiple server certs are used (eg. when making use of SNI), and
// this is left to the caller to determine.
//
// serverCert may be nil when requesting TLSChannelBindingUnique or TLSChannelBindingExporter binding.
//
// A request for TLSChannelBindingUnique will fail if TLS1.3 is in use, or if
// session resumption is enabled.
//
// A request for TLSChannelBindingEndpoint will fail if no serverCert is supplied.
//
// The returned data is suitable for passing to SASL or GSSAPI authentication
// mechanisms.
//
// Note that it is the caller's responsibility to ensure that session renegotiation
// does not occur between the time that MakeTLSChannelBinding() is called and the
// end of the authentication phase of the application protocol.
func MakeTLSChannelBinding(state tls.ConnectionState, serverCert *x509.Certificate, bindingType TLSChannelBindingType) (cbData []byte, err error) {
	var prefix string
	var data []byte

	switch bindingType {
	case TLSChannelBindingNone:
		return nil, nil
	case TLSChannelBindingUnique:
		// RFC 5929 § 3
		prefix = "tls-unique:"

		// not supported for >= TLSv1.3
		if state.Version > 0x0303 {
			return nil, fmt.Errorf("tls-unique channel binding not supported for TLS version %s", tlsVerName(state.Version))
		}

		if state.TLSUnique == nil {
			if state.DidResume {
				return nil, errors.New("channel-binding not available for resumed sessions")
			}
			return nil, errors.New("channel-binding not available")
		}

		data = state.TLSUnique

	case TLSChannelBindingEndpoint:
		// RFC 5929 § 4
		prefix = "tls-server-end-point:"

		if serverCert == nil {
			return nil, errors.New("must supply server cert for tls-server-endpoint channel-binding")
		}

		// choose the channel binding hash type
		// Use the same hash type used for the certificate signature, except for MD5 and SHA-1 which
		// use SHA256
		hashType := crypto.SHA256
		switch serverCert.SignatureAlgorithm {
		case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
			hashType = crypto.SHA384
		case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
			hashType = crypto.SHA512
		}

		hasher := hashType.New()
		_, _ = hasher.Write(serverCert.Raw)
		data = hasher.Sum(nil)

	case TLSChannelBindingExporter:
		prefix = "tls-exporter:"

		// RFC 9266 § 2
		data, err = state.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("bad channel binding type")
	}

	cbData = make([]byte, len(prefix)+len(data))
	copy(cbData, prefix)
	copy(cbData[len(prefix):], data)

	return cbData, nil
}

func tlsVerName(ver uint16) string {
	switch ver {
	case tls.VersionSSL30: //nolint:staticcheck // SSL30 is deprecated
		return "SSL v3"
	case tls.VersionTLS10:
		return "TlS v1.0"
	case tls.VersionTLS11:
		return "TLS v1.1"
	case tls.VersionTLS12:
		return "TLS v1.2"
	case tls.VersionTLS13:
		return "TLS v1.3"
	default:
		return fmt.Sprintf("Unknown TLS version (%x)", ver)
	}
}
