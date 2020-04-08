package gocircomprover

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify1(t *testing.T) {
	proofJson, err := ioutil.ReadFile("testdata/big/proof.json")
	require.Nil(t, err)
	vkJson, err := ioutil.ReadFile("testdata/big/verification_key.json")
	require.Nil(t, err)
	publicJson, err := ioutil.ReadFile("testdata/big/public.json")
	require.Nil(t, err)

	public, err := ParsePublicSignals(publicJson)
	require.Nil(t, err)
	proof, err := ParseProof(proofJson)
	require.Nil(t, err)
	vk, err := ParseVk(vkJson)
	require.Nil(t, err)

	v := Verify(vk, proof, public)
	assert.True(t, v)
}
