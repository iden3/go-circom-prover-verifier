package prover

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/iden3/go-circom-prover-verifier/parsers"
	"github.com/iden3/go-circom-prover-verifier/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCircuitsGenerateProof(t *testing.T) {
	testCircuitGenerateProof(t, "circuit1k") // 1000 constraints
	testCircuitGenerateProof(t, "circuit5k") // 5000 constraints
	// testCircuitGenerateProof(t, "circuit10k") // 10000 constraints
	// testCircuitGenerateProof(t, "circuit20k") // 20000 constraints
}

func testCircuitGenerateProof(t *testing.T, circuit string) {
	provingKeyJson, err := ioutil.ReadFile("../testdata/" + circuit + "/proving_key.json")
	require.Nil(t, err)
	pk, err := parsers.ParsePk(provingKeyJson)
	require.Nil(t, err)

	witnessJson, err := ioutil.ReadFile("../testdata/" + circuit + "/witness.json")
	require.Nil(t, err)
	w, err := parsers.ParseWitness(witnessJson)
	require.Nil(t, err)

	beforeT := time.Now()
	proof, pubSignals, err := GenerateProof(pk, w)
	assert.Nil(t, err)
	fmt.Println("proof generation time elapsed:", time.Since(beforeT))

	proofStr, err := parsers.ProofToJson(proof)
	assert.Nil(t, err)

	err = ioutil.WriteFile("../testdata/"+circuit+"/proof.json", proofStr, 0644)
	assert.Nil(t, err)
	publicStr, err := json.Marshal(parsers.ArrayBigIntToString(pubSignals))
	assert.Nil(t, err)
	err = ioutil.WriteFile("../testdata/"+circuit+"/public.json", publicStr, 0644)
	assert.Nil(t, err)

	// verify the proof
	vkJson, err := ioutil.ReadFile("../testdata/" + circuit + "/verification_key.json")
	require.Nil(t, err)
	vk, err := parsers.ParseVk(vkJson)
	require.Nil(t, err)

	v := verifier.Verify(vk, proof, pubSignals)
	assert.True(t, v)

	// to verify the proof with snarkjs:
	// snarkjs verify --vk testdata/circuitX/verification_key.json -p testdata/circuitX/proof.json --pub testdata/circuitX/public.json
}

func BenchmarkGenerateProof(b *testing.B) {
	// benchmark with a circuit of 10000 constraints
	provingKeyJson, err := ioutil.ReadFile("../testdata/circuit1/proving_key.json")
	require.Nil(b, err)
	pk, err := parsers.ParsePk(provingKeyJson)
	require.Nil(b, err)

	witnessJson, err := ioutil.ReadFile("../testdata/circuit1/witness.json")
	require.Nil(b, err)
	w, err := parsers.ParseWitness(witnessJson)
	require.Nil(b, err)

	for i := 0; i < b.N; i++ {
		GenerateProof(pk, w)
	}
}
