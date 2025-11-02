// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"crypto/tls"
	"testing"

	cb "github.com/golang-auth/go-channelbinding"
	"github.com/stretchr/testify/assert"
)

func TestNone(t *testing.T) {
	var state tls.ConnectionState
	cbData, err := cb.MakeTLSChannelBinding(state, nil, cb.TLSChannelBindingNone)
	assert.Nil(t, err, "none binding type should not return an error")
	assert.Nil(t, cbData, "none binding type should not return data")
}
