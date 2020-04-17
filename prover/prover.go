package prover

import (
	"crypto/rand"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/iden3/go-circom-prover-verifier/types"
)

// Proof is the data structure of the Groth16 zkSNARK proof
type Proof struct {
	A *bn256.G1
	B *bn256.G2
	C *bn256.G1
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

// R is the mod of the finite field
var R, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

func randBigInt() (*big.Int, error) {
	maxbits := R.BitLen()
	b := make([]byte, (maxbits/8)-1)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(b)
	rq := new(big.Int).Mod(r, R)

	return rq, nil
}

// GenerateProof generates the Groth16 zkSNARK proof
func GenerateProof(pk *types.Pk, w types.Witness) (*types.Proof, []*big.Int, error) {
	var proof types.Proof

	r, err := randBigInt()
	if err != nil {
		return nil, nil, err
	}
	s, err := randBigInt()
	if err != nil {
		return nil, nil, err
	}

	proof.A = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	proof.B = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	proof.C = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	proofBG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))

	for i := 0; i < pk.NVars; i++ {
		proof.A = new(bn256.G1).Add(proof.A, new(bn256.G1).ScalarMult(pk.A[i], w[i]))
		proof.B = new(bn256.G2).Add(proof.B, new(bn256.G2).ScalarMult(pk.B2[i], w[i]))
		proofBG1 = new(bn256.G1).Add(proofBG1, new(bn256.G1).ScalarMult(pk.B1[i], w[i]))
	}

	for i := pk.NPublic + 1; i < pk.NVars; i++ {
		proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(pk.C[i], w[i]))
	}

	proof.A = new(bn256.G1).Add(proof.A, pk.VkAlpha1)
	proof.A = new(bn256.G1).Add(proof.A, new(bn256.G1).ScalarMult(pk.VkDelta1, r))

	proof.B = new(bn256.G2).Add(proof.B, pk.VkBeta2)
	proof.B = new(bn256.G2).Add(proof.B, new(bn256.G2).ScalarMult(pk.VkDelta2, s))

	proofBG1 = new(bn256.G1).Add(proofBG1, pk.VkBeta1)
	proofBG1 = new(bn256.G1).Add(proofBG1, new(bn256.G1).ScalarMult(pk.VkDelta1, s))

	h := calculateH(pk, w)

	for i := 0; i < len(h); i++ {
		proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(pk.HExps[i], h[i]))
	}
	proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(proof.A, s))
	proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(proofBG1, r))
	rsneg := new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Mul(r, s)), R) // fAdd & fMul
	proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(pk.VkDelta1, rsneg))

	pubSignals := w[1 : pk.NPublic+1]

	return &proof, pubSignals, nil
}

func calculateH(pk *types.Pk, w types.Witness) []*big.Int {
	m := pk.DomainSize
	polAT := arrayOfZeroes(m)
	polBT := arrayOfZeroes(m)
	polCT := arrayOfZeroes(m)

	for i := 0; i < pk.NVars; i++ {
		for j := range pk.PolsA[i] {
			polAT[j] = fAdd(polAT[j], fMul(w[i], pk.PolsA[i][j]))
		}
		for j := range pk.PolsB[i] {
			polBT[j] = fAdd(polBT[j], fMul(w[i], pk.PolsB[i][j]))
		}
		for j := range pk.PolsC[i] {
			polCT[j] = fAdd(polCT[j], fMul(w[i], pk.PolsC[i][j]))
		}
	}
	polAS := ifft(polAT)
	polBS := ifft(polBT)

	polABS := polynomialMul(polAS, polBS)
	polCS := ifft(polCT)
	polABCS := polynomialSub(polABS, polCS)

	hS := polABCS[m:]
	return hS
}
