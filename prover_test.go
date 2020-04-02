package gocircomprover

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProve(t *testing.T) {
	provingKeyJson, err := ioutil.ReadFile("testdata/provingkey.json")
	require.Nil(t, err)
	pk, err := ParseProvingKey(provingKeyJson)
	require.Nil(t, err)

	fmt.Println("polsA", pk.PolsA)
	fmt.Println("polsB", pk.PolsB)
	fmt.Println("polsC", pk.PolsC)

	witnessJson, err := ioutil.ReadFile("testdata/witness.json")
	require.Nil(t, err)
	w, err := ParseWitness(witnessJson)
	require.Nil(t, err)

	fmt.Println("w", w)
	assert.Equal(t, Witness{big.NewInt(1), big.NewInt(33), big.NewInt(3), big.NewInt(11)}, w)

	proof, pubSignals, err := Prove(pk, w)
	assert.Nil(t, err)
	fmt.Println("proof", proof)
	fmt.Println("pubSignals", pubSignals)
}
