package types

import (
	"encoding/hex"
	"encoding/json"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

var Q, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

// R is the mod of the finite field
var R, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Proof is the data structure of the Groth16 zkSNARK proof
type Proof struct {
	A *bn256.G1
	B *bn256.G2
	C *bn256.G1
}

type proofAux struct {
	A string `json:"pi_a"`
	B string `json:"pi_b"`
	C string `json:"pi_c"`
}

func (p Proof) MarshalJSON() ([]byte, error) {
	var pa proofAux
	pa.A = hex.EncodeToString(p.A.Marshal())
	pa.B = hex.EncodeToString(p.B.Marshal())
	pa.C = hex.EncodeToString(p.C.Marshal())
	return json.Marshal(pa)
}

func (p *Proof) UnmarshalJSON(data []byte) error {
	var pa proofAux
	if err := json.Unmarshal(data, &pa); err != nil {
		return err
	}
	aBytes, err := hex.DecodeString(pa.A)
	if err != nil {
		return err
	}
	p.A = new(bn256.G1)
	if _, err := p.A.Unmarshal(aBytes); err != nil {
		return err
	}
	bBytes, err := hex.DecodeString(pa.B)
	if err != nil {
		return err
	}
	p.B = new(bn256.G2)
	if _, err := p.B.Unmarshal(bBytes); err != nil {
		return err
	}
	cBytes, err := hex.DecodeString(pa.C)
	if err != nil {
		return err
	}
	p.C = new(bn256.G1)
	if _, err := p.C.Unmarshal(cBytes); err != nil {
		return err
	}
	return nil
}

// Pk holds the data structure of the ProvingKey
type Pk struct {
	A          []*bn256.G1
	B2         []*bn256.G2
	B1         []*bn256.G1
	C          []*bn256.G1
	NVars      int
	NPublic    int
	VkAlpha1   *bn256.G1
	VkDelta1   *bn256.G1
	VkBeta1    *bn256.G1
	VkBeta2    *bn256.G2
	VkDelta2   *bn256.G2
	HExps      []*bn256.G1
	DomainSize int
	PolsA      []map[int]*big.Int
	PolsB      []map[int]*big.Int
	PolsC      []map[int]*big.Int
}

// Witness contains the witness
type Witness []*big.Int

// Vk is the Verification Key data structure
type Vk struct {
	Alpha *bn256.G1
	Beta  *bn256.G2
	Gamma *bn256.G2
	Delta *bn256.G2
	IC    []*bn256.G1
}
