// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	cb "github.com/golang-auth/go-channelbinding"
	"github.com/stretchr/testify/assert"
)

func TestEndpoint(t *testing.T) {
	var tests = []struct {
		name           string
		stateData      string
		expectedCbData string
		shouldSucceed  bool
	}{
		{"MD5 Digest/TLS1.2", EndpointMD5TLS12State, EndpointMD5TLS12CBData, true},
		{"MD5 Digest/TLS1.3", EndpointMD5TLS13State, EndpointMD5TLS13CBData, true},
		{"SHA1 Digest/TLS1.2", EndpointSHA1TLS12State, EndpointSHA1TLS12CBData, true},
		{"SHA1 Digest/TLS1.3", EndpointSHA1TLS13State, EndpointSHA1TLS13CBData, true},
		{"SHA256 Digest/TLS1.2", EndpointSHA256TLS12State, EndpointSHA256TLS12CBData, true},
		{"SHA256 Digest/TLS1.3", EndpointSHA256TLS13State, EndpointSHA256TLS13CBData, true},
	}

	var state tls.ConnectionState
	_, err := cb.MakeTLSChannelBinding(state, nil, cb.TLSChannelBindingEndpoint)
	assert.Error(t, err, "endpoint binding should fail when no server cert provided")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stateData, cbWantData []byte
			var err error
			stateData, err = base64.StdEncoding.DecodeString(tt.stateData)
			assert.NoError(t, err, "failed to decode test data")
			cbWantData, err = hex.DecodeString(tt.expectedCbData)
			assert.NoError(t, err, "failed to decode test data")

			var state tls.ConnectionState
			err = json.Unmarshal(stateData, &state)
			assert.NoError(t, err, "failed to unmarshal test data")

			cbData, err := cb.MakeTLSChannelBinding(state, state.PeerCertificates[0], cb.TLSChannelBindingEndpoint)
			if tt.shouldSucceed {
				assert.NoError(t, err, "failed to make channel binding data")
				assert.Equal(t, cbWantData, cbData, "channel binding data mismatch")
			} else {
				assert.Error(t, err, "should fail to create channel binding data")
				assert.Nil(t, cbData)
			}
		})
	}
}
