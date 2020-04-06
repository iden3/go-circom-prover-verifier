# go-circom-prover [![GoDoc](https://godoc.org/github.com/iden3/go-circom-prover?status.svg)](https://godoc.org/github.com/iden3/go-circom-prover) [![Go Report Card](https://goreportcard.com/badge/github.com/iden3/go-circom-prover)](https://goreportcard.com/report/github.com/iden3/go-circom-prover)

Experimental Go implementation of the [Groth16 protocol](https://eprint.iacr.org/2016/260.pdf) zkSNARK prover compatible with [circom](https://github.com/iden3/circom).


Using [bn256](https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256/cloudflare) (used by [go-ethereum](https://github.com/ethereum/go-ethereum)) for the Pairing curve operations.

### Example

```go
// read ProvingKey & Witness files
provingKeyJson, _ := ioutil.ReadFile("testdata/provingkey.json")
witnessJson, _ := ioutil.ReadFile("testdata/witness.json")

// parse Proving Key
pk, _ := circomprover.ParseProvingKey(provingKeyJson)

// parse Witness
w, _ := circomprover.ParseWitness(witnessJson)

// generate the proof
proof, pubSignals, err := circomprover.GenerateProof(pk, w)
assert.Nil(t, err)

proofStr, err := circomprover.ProofToString(proof)
assert.Nil(t, err)
publicStr, err := json.Marshal(circomprover.ArrayBigIntToString(pubSignals)
assert.Nil(t, err)

fmt.Println(proofStr)
fmt.Println(publicStr)
```
