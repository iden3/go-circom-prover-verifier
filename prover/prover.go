package prover

import (
	"crypto/rand"
	"math"
	"math/big"
	"sync"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/iden3/go-circom-prover-verifier/types"
	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/utils"
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

func randBigInt() (*big.Int, error) {
	maxbits := types.R.BitLen()
	b := make([]byte, (maxbits/8)-1)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(b)
	rq := new(big.Int).Mod(r, types.R)

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

	var waitGroup sync.WaitGroup
	waitGroup.Add(4)
	go func(wg *sync.WaitGroup) {
		for i := 0; i < pk.NVars; i++ {
			proof.A = new(bn256.G1).Add(proof.A, new(bn256.G1).ScalarMult(pk.A[i], w[i]))
		}
		wg.Done()
	}(&waitGroup)
	go func(wg *sync.WaitGroup) {
		for i := 0; i < pk.NVars; i++ {
			proof.B = new(bn256.G2).Add(proof.B, new(bn256.G2).ScalarMult(pk.B2[i], w[i]))
		}
		wg.Done()
	}(&waitGroup)
	go func(wg *sync.WaitGroup) {
		for i := 0; i < pk.NVars; i++ {
			proofBG1 = new(bn256.G1).Add(proofBG1, new(bn256.G1).ScalarMult(pk.B1[i], w[i]))
		}
		wg.Done()
	}(&waitGroup)
	go func(wg *sync.WaitGroup) {
		for i := pk.NPublic + 1; i < pk.NVars; i++ {
			proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(pk.C[i], w[i]))
		}
		wg.Done()
	}(&waitGroup)
	waitGroup.Wait()

	h := calculateH(pk, w)

	var waitGroup2 sync.WaitGroup
	waitGroup2.Add(2)
	go func(wg *sync.WaitGroup) {
		proof.A = new(bn256.G1).Add(proof.A, pk.VkAlpha1)
		proof.A = new(bn256.G1).Add(proof.A, new(bn256.G1).ScalarMult(pk.VkDelta1, r))

		proof.B = new(bn256.G2).Add(proof.B, pk.VkBeta2)
		proof.B = new(bn256.G2).Add(proof.B, new(bn256.G2).ScalarMult(pk.VkDelta2, s))

		proofBG1 = new(bn256.G1).Add(proofBG1, pk.VkBeta1)
		proofBG1 = new(bn256.G1).Add(proofBG1, new(bn256.G1).ScalarMult(pk.VkDelta1, s))
		wg.Done()
	}(&waitGroup2)
	go func(wg *sync.WaitGroup) {
		for i := 0; i < len(h); i++ {
			proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(pk.HExps[i], h[i]))
		}
		wg.Done()
	}(&waitGroup2)
	waitGroup2.Wait()

	proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(proof.A, s))
	proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(proofBG1, r))
	rsneg := new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Mul(r, s)), types.R) // fAdd & fMul
	proof.C = new(bn256.G1).Add(proof.C, new(bn256.G1).ScalarMult(pk.VkDelta1, rsneg))

	pubSignals := w[1 : pk.NPublic+1]

	return &proof, pubSignals, nil
}

func calculateH(pk *types.Pk, w types.Witness) []*big.Int {
	m := pk.DomainSize
	polAT := arrayOfZeroes(m)
	polBT := arrayOfZeroes(m)

	for i := 0; i < pk.NVars; i++ {
		for j := range pk.PolsA[i] {
			polAT[j] = fAdd(polAT[j], fMul(w[i], pk.PolsA[i][j]))
		}
		for j := range pk.PolsB[i] {
			polBT[j] = fAdd(polBT[j], fMul(w[i], pk.PolsB[i][j]))
		}
	}
	polATe := utils.BigIntArrayToElementArray(polAT)
	polBTe := utils.BigIntArrayToElementArray(polBT)

	polASe := ifft(polATe)
	polBSe := ifft(polBTe)

	r := int(math.Log2(float64(m))) + 1
	roots := newRootsT()
	roots.setRoots(r)
	for i := 0; i < len(polASe); i++ {
		polASe[i] = ff.NewElement().Mul(polASe[i], roots.roots[r][i])
		polBSe[i] = ff.NewElement().Mul(polBSe[i], roots.roots[r][i])
	}

	polATodd := fft(polASe)
	polBTodd := fft(polBSe)

	polABT := arrayOfZeroesE(len(polASe) * 2)
	for i := 0; i < len(polASe); i++ {
		polABT[2*i] = ff.NewElement().Mul(polATe[i], polBTe[i])
		polABT[2*i+1] = ff.NewElement().Mul(polATodd[i], polBTodd[i])
	}

	hSeFull := ifft(polABT)

	hSe := hSeFull[m:]
	return utils.ElementArrayToBigIntArray(hSe)
}
