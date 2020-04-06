package gocircomprover

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSmallCircuitGenerateProf(t *testing.T) {
	provingKeyJson, err := ioutil.ReadFile("testdata/small/proving_key.json")
	require.Nil(t, err)
	pk, err := ParseProvingKey(provingKeyJson)
	require.Nil(t, err)

	fmt.Println("polsA", pk.PolsA)
	fmt.Println("polsB", pk.PolsB)
	fmt.Println("polsC", pk.PolsC)

	witnessJson, err := ioutil.ReadFile("testdata/small/witness.json")
	require.Nil(t, err)
	w, err := ParseWitness(witnessJson)
	require.Nil(t, err)

	assert.Equal(t, Witness{big.NewInt(1), big.NewInt(33), big.NewInt(3), big.NewInt(11)}, w)

	proof, pubSignals, err := GenerateProof(pk, w)
	assert.Nil(t, err)
	fmt.Println("proof", proof)
	fmt.Println("pubSignals", pubSignals)

	proofStr, err := ProofToJson(proof)
	assert.Nil(t, err)
	fmt.Println("prover\n", string(proofStr))

	err = ioutil.WriteFile("testdata/small/proof.json", proofStr, 0644)
	assert.Nil(t, err)
	publicStr, err := json.Marshal(ArrayBigIntToString(pubSignals))
	assert.Nil(t, err)
	err = ioutil.WriteFile("testdata/small/public.json", publicStr, 0644)
	assert.Nil(t, err)

	// to verify the proof:
	// snarkjs verify --vk testdata/small/verification_key.json -p testdata/small/proof.json --pub testdata/small/public.json
}

func TestBigCircuitGenerateProf(t *testing.T) {
	provingKeyJson, err := ioutil.ReadFile("testdata/big/proving_key.json")
	require.Nil(t, err)
	pk, err := ParseProvingKey(provingKeyJson)
	require.Nil(t, err)

	witnessJson, err := ioutil.ReadFile("testdata/big/witness.json")
	require.Nil(t, err)
	w, err := ParseWitness(witnessJson)
	require.Nil(t, err)

	proof, pubSignals, err := GenerateProof(pk, w)
	assert.Nil(t, err)
	fmt.Println("proof", proof)
	fmt.Println("pubSignals", pubSignals)

	proofStr, err := ProofToJson(proof)
	assert.Nil(t, err)
	fmt.Println("prover\n", string(proofStr))

	err = ioutil.WriteFile("testdata/big/proof.json", proofStr, 0644)
	assert.Nil(t, err)
	publicStr, err := json.Marshal(ArrayBigIntToString(pubSignals))
	assert.Nil(t, err)
	err = ioutil.WriteFile("testdata/big/public.json", publicStr, 0644)
	assert.Nil(t, err)

	// to verify the proof:
	// snarkjs verify --vk testdata/big/verification_key.json -p testdata/big/proof.json --pub testdata/big/public.json
}
