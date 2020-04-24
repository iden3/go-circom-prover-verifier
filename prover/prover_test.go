package prover

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"
	"time"

	"github.com/iden3/go-circom-prover-verifier/parsers"
	"github.com/iden3/go-circom-prover-verifier/types"
	"github.com/iden3/go-circom-prover-verifier/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSmallCircuitGenerateProof(t *testing.T) {
	provingKeyJson, err := ioutil.ReadFile("../testdata/small/proving_key.json")
	require.Nil(t, err)
	pk, err := parsers.ParsePk(provingKeyJson)
	require.Nil(t, err)

	witnessJson, err := ioutil.ReadFile("../testdata/small/witness.json")
	require.Nil(t, err)
	w, err := parsers.ParseWitness(witnessJson)
	require.Nil(t, err)

	assert.Equal(t, types.Witness{big.NewInt(1), big.NewInt(33), big.NewInt(3), big.NewInt(11)}, w)

	beforeT := time.Now()
	proof, pubSignals, err := GenerateProof(pk, w)
	assert.Nil(t, err)
	fmt.Println("proof generation time elapsed:", time.Since(beforeT))

	proofStr, err := parsers.ProofToJson(proof)
	assert.Nil(t, err)

	err = ioutil.WriteFile("../testdata/small/proof.json", proofStr, 0644)
	assert.Nil(t, err)
	publicStr, err := json.Marshal(parsers.ArrayBigIntToString(pubSignals))
	assert.Nil(t, err)
	err = ioutil.WriteFile("../testdata/small/public.json", publicStr, 0644)
	assert.Nil(t, err)

	// verify the proof
	vkJson, err := ioutil.ReadFile("../testdata/small/verification_key.json")
	require.Nil(t, err)
	vk, err := parsers.ParseVk(vkJson)
	require.Nil(t, err)

	v := verifier.Verify(vk, proof, pubSignals)
	assert.True(t, v)

	// to verify the proof with snarkjs:
	// snarkjs verify --vk testdata/small/verification_key.json -p testdata/small/proof.json --pub testdata/small/public.json
}

func TestBigCircuitGenerateProof(t *testing.T) {
	provingKeyJson, err := ioutil.ReadFile("../testdata/big/proving_key.json")
	require.Nil(t, err)
	pk, err := parsers.ParsePk(provingKeyJson)
	require.Nil(t, err)

	witnessJson, err := ioutil.ReadFile("../testdata/big/witness.json")
	require.Nil(t, err)
	w, err := parsers.ParseWitness(witnessJson)
	require.Nil(t, err)

	beforeT := time.Now()
	proof, pubSignals, err := GenerateProof(pk, w)
	assert.Nil(t, err)
	fmt.Println("proof generation time elapsed:", time.Since(beforeT))

	proofStr, err := parsers.ProofToJson(proof)
	assert.Nil(t, err)

	err = ioutil.WriteFile("../testdata/big/proof.json", proofStr, 0644)
	assert.Nil(t, err)
	publicStr, err := json.Marshal(parsers.ArrayBigIntToString(pubSignals))
	assert.Nil(t, err)
	err = ioutil.WriteFile("../testdata/big/public.json", publicStr, 0644)
	assert.Nil(t, err)

	// verify the proof
	vkJson, err := ioutil.ReadFile("../testdata/big/verification_key.json")
	require.Nil(t, err)
	vk, err := parsers.ParseVk(vkJson)
	require.Nil(t, err)

	v := verifier.Verify(vk, proof, pubSignals)
	assert.True(t, v)

	// to verify the proof with snarkjs:
	// snarkjs verify --vk testdata/big/verification_key.json -p testdata/big/proof.json --pub testdata/big/public.json
}

func TestIdStateCircuitGenerateProof(t *testing.T) {
	// this test is to execute the proof generation for a bigger circuit
	// (arround 22500 constraints)
	//
	// to see the time needed to execute this
	// test Will need the ../testdata/idstate-circuit compiled &
	// trustedsetup files (generated in
	// https://github.com/iden3/go-zksnark-full-flow-example)
	if false {
		fmt.Println("\nTestIdStateCircuitGenerateProof activated")
		provingKeyJson, err := ioutil.ReadFile("../testdata/idstate-circuit/proving_key.json")
		require.Nil(t, err)
		pk, err := parsers.ParsePk(provingKeyJson)
		require.Nil(t, err)

		witnessJson, err := ioutil.ReadFile("../testdata/idstate-circuit/witness.json")
		require.Nil(t, err)
		w, err := parsers.ParseWitness(witnessJson)
		require.Nil(t, err)

		beforeT := time.Now()
		proof, pubSignals, err := GenerateProof(pk, w)
		assert.Nil(t, err)
		fmt.Println("proof generation time elapsed:", time.Since(beforeT))

		proofStr, err := parsers.ProofToJson(proof)
		assert.Nil(t, err)

		err = ioutil.WriteFile("../testdata/idstate-circuit/proof.json", proofStr, 0644)
		assert.Nil(t, err)
		publicStr, err := json.Marshal(parsers.ArrayBigIntToString(pubSignals))
		assert.Nil(t, err)
		err = ioutil.WriteFile("../testdata/idstate-circuit/public.json", publicStr, 0644)
		assert.Nil(t, err)

		// verify the proof
		vkJson, err := ioutil.ReadFile("../testdata/idstate-circuit/verification_key.json")
		require.Nil(t, err)
		vk, err := parsers.ParseVk(vkJson)
		require.Nil(t, err)

		v := verifier.Verify(vk, proof, pubSignals)
		assert.True(t, v)
	}
}

func BenchmarkGenerateProof(b *testing.B) {
	provingKeyJson, err := ioutil.ReadFile("../testdata/big/proving_key.json")
	require.Nil(b, err)
	pk, err := parsers.ParsePk(provingKeyJson)
	require.Nil(b, err)

	witnessJson, err := ioutil.ReadFile("../testdata/big/witness.json")
	require.Nil(b, err)
	w, err := parsers.ParseWitness(witnessJson)
	require.Nil(b, err)

	for i := 0; i < b.N; i++ {
		GenerateProof(pk, w)
	}
}
