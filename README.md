# go-circom-prover-verifier [![GoDoc](https://godoc.org/github.com/iden3/go-circom-prover-verifier?status.svg)](https://godoc.org/github.com/iden3/go-circom-prover-verifier) [![Go Report Card](https://goreportcard.com/badge/github.com/iden3/go-circom-prover-verifier)](https://goreportcard.com/report/github.com/iden3/go-circom-prover-verifier) [![Test](https://github.com/iden3/go-circom-prover-verifier/workflows/Test/badge.svg)](https://github.com/iden3/go-circom-prover-verifier/actions?query=workflow%3ATest)

Experimental Go implementation of the [Groth16 protocol](https://eprint.iacr.org/2016/260.pdf) zkSNARK prover & verifier compatible with [circom](https://github.com/iden3/circom).


Using [bn256](https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256/cloudflare) (used by [go-ethereum](https://github.com/ethereum/go-ethereum)) for the Pairing curve operations.

### Example

- Generate Proof
```go
import (
  "github.com/iden3/go-circom-prover-verifier/parsers"
  "github.com/iden3/go-circom-prover-verifier/prover"
  "github.com/iden3/go-circom-prover-verifier/verifier"
)

[...]

// read ProvingKey & Witness files
provingKeyJson, _ := ioutil.ReadFile("../testdata/small/proving_key.json")
witnessJson, _ := ioutil.ReadFile("../testdata/small/witness.json")

// parse Proving Key
pk, _ := parsers.ParsePk(provingKeyJson)

// parse Witness
w, _ := parsers.ParseWitness(witnessJson)

// generate the proof
proof, pubSignals, _ := prover.GenerateProof(pk, w)

// print proof & publicSignals
proofStr, _ := parsers.ProofToJson(proof)
publicStr, _ := json.Marshal(parsers.ArrayBigIntToString(pubSignals))
fmt.Println(proofStr)
fmt.Println(publicStr)
```

- Verify Proof
```go
// read proof & verificationKey & publicSignals
proofJson, _ := ioutil.ReadFile("../testdata/big/proof.json")
vkJson, _ := ioutil.ReadFile("../testdata/big/verification_key.json")
publicJson, _ := ioutil.ReadFile("../testdata/big/public.json")

// parse proof & verificationKey & publicSignals
public, _ := parsers.ParsePublicSignals(publicJson)
proof, _ := parsers.ParseProof(proofJson)
vk, _ := parsers.ParseVk(vkJson)

// verify the proof with the given verificationKey & publicSignals
v := verifier.Verify(vk, proof, public)
fmt.Println(v)
```

## CLI

From the `cli` directory:

- Show options
```
> go run cli.go -help
go-circom-prover-verifier
                 v0.0.1
Usage of /tmp/go-build620318239/b001/exe/cli:
  -proof string
        proof path (default "proof.json")
  -prove
        prover mode
  -provingkey string
        provingKey path (default "proving_key.json")
  -public string
        public signals path (default "public.json")
  -verificationkey string
        verificationKey path (default "verification_key.json")
  -verify
        verifier mode
  -witness string
        witness path (default "witness.json")
```

- Prove
```
> go run cli.go -prove -provingkey=../testdata/small/proving_key.json -witness=../testdata/small/witness.json
```
- Verify
```
> go run cli.go -verify -verificationkey=../testdata/small/verification_key.json
```
