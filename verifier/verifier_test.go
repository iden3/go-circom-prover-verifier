package verifier

import (
	"io/ioutil"
	"testing"

	"github.com/iden3/go-circom-prover-verifier/parsers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify1(t *testing.T) {
	proofJson, err := ioutil.ReadFile("../testdata/big/proof.json")
	require.Nil(t, err)
	vkJson, err := ioutil.ReadFile("../testdata/big/verification_key.json")
	require.Nil(t, err)
	publicJson, err := ioutil.ReadFile("../testdata/big/public.json")
	require.Nil(t, err)

	public, err := parsers.ParsePublicSignals(publicJson)
	require.Nil(t, err)
	proof, err := parsers.ParseProof(proofJson)
	require.Nil(t, err)
	vk, err := parsers.ParseVk(vkJson)
	require.Nil(t, err)

	v := Verify(vk, proof, public)
	assert.True(t, v)
}

func BenchmarkVerify(b *testing.B) {
	proofJson, err := ioutil.ReadFile("../testdata/big/proof.json")
	require.Nil(b, err)
	vkJson, err := ioutil.ReadFile("../testdata/big/verification_key.json")
	require.Nil(b, err)
	publicJson, err := ioutil.ReadFile("../testdata/big/public.json")
	require.Nil(b, err)

	public, err := parsers.ParsePublicSignals(publicJson)
	require.Nil(b, err)
	proof, err := parsers.ParseProof(proofJson)
	require.Nil(b, err)
	vk, err := parsers.ParseVk(vkJson)
	require.Nil(b, err)

	for i := 0; i < b.N; i++ {
		Verify(vk, proof, public)
	}
}
