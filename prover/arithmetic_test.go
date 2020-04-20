package prover

import (
	"crypto/rand"
	"math/big"
	"testing"

	cryptoConstants "github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/utils"
)

func randBI() *big.Int {
	maxbits := 253
	b := make([]byte, (maxbits/8)-1)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	r := new(big.Int).SetBytes(b)
	return new(big.Int).Mod(r, cryptoConstants.Q)
}

func BenchmarkArithmetic(b *testing.B) {
	// generate arrays with bigint
	var p, q []*big.Int
	for i := 0; i < 1000; i++ {
		pi := randBI()
		p = append(p, pi)
	}
	for i := 1000 - 1; i >= 0; i-- {
		q = append(q, p[i])
	}
	pe := utils.BigIntArrayToElementArray(p)
	qe := utils.BigIntArrayToElementArray(q)

	b.Run("polynomialSub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			polynomialSub(p, q)
		}
	})
	b.Run("polynomialSubE", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			polynomialSubE(pe, qe)
		}
	})
	b.Run("polynomialMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			polynomialMul(p, q)
		}
	})
	b.Run("polynomialMulE", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			polynomialMulE(pe, qe)
		}
	})
	b.Run("polynomialDiv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			polynomialDiv(p, q)
		}
	})
	b.Run("polynomialDivE", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			polynomialDivE(pe, qe)
		}
	})
}
