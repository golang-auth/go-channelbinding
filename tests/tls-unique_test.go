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

func TestUniqueTLS12(t *testing.T) {
	stateData, err := base64.StdEncoding.DecodeString(UniqueSHA256TLS12State)
	assert.NoError(t, err, "failed to decode test data")
	cbWantData, err := hex.DecodeString(UniqueSHA256TLS12CBdata)
	assert.NoError(t, err, "failed to decode test data")

	var state tls.ConnectionState
	err = json.Unmarshal(stateData, &state)
	assert.NoError(t, err, "failed to unmarshal test data")

	cbData, err := cb.MakeTLSChannelBinding(state, nil, cb.TLSChannelBindingUnique)
	assert.NoError(t, err, "failed to make channel binding data")
	assert.Equal(t, cbWantData, cbData, "channel binding data mismatch")
}

func TestUniqueTLS13(t *testing.T) {
	stateData, err := base64.StdEncoding.DecodeString(UniqueSHA256TLS13State)
	assert.NoError(t, err, "failed to decode test data")

	var state tls.ConnectionState
	err = json.Unmarshal(stateData, &state)
	assert.NoError(t, err, "failed to unmarshal test data")

	cbData, err := cb.MakeTLSChannelBinding(state, nil, cb.TLSChannelBindingUnique)
	assert.Error(t, err, "tls-unique should fail with TLS1.3")
	assert.Nil(t, cbData)
}

func TestUniqueBadState(t *testing.T) {
	stateData, err := base64.StdEncoding.DecodeString(UniqueSHA256TLS12State)
	assert.NoError(t, err, "failed to decode test data")

	var state tls.ConnectionState
	err = json.Unmarshal(stateData, &state)
	assert.NoError(t, err, "failed to unmarshal test data")

	state.TLSUnique = nil
	_, err = cb.MakeTLSChannelBinding(state, nil, cb.TLSChannelBindingUnique)
	assert.Error(t, err, "tls-unique should fail with bad state")

	state.DidResume = true
	_, err = cb.MakeTLSChannelBinding(state, nil, cb.TLSChannelBindingUnique)
	assert.Error(t, err, "tls-unique should fail with resumed session")
}
