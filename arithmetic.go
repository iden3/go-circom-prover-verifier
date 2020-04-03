package gocircomprover

import (
	"bytes"
	"math/big"
)

func arrayOfZeroes(n int) []*big.Int {
	var r []*big.Int
	for i := 0; i < n; i++ {
		r = append(r, new(big.Int).SetInt64(0))
	}
	return r
}

func fAdd(a, b *big.Int) *big.Int {
	ab := new(big.Int).Add(a, b)
	return new(big.Int).Mod(ab, R)
}

func fSub(a, b *big.Int) *big.Int {
	ab := new(big.Int).Sub(a, b)
	return new(big.Int).Mod(ab, R)
}

func fMul(a, b *big.Int) *big.Int {
	ab := new(big.Int).Mul(a, b)
	return new(big.Int).Mod(ab, R)
}

func fDiv(a, b *big.Int) *big.Int {
	ab := new(big.Int).Mul(a, new(big.Int).ModInverse(b, R))
	return new(big.Int).Mod(ab, R)
}

func fNeg(a *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Neg(a), R)
}

func fInv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, R)
}

func fExp(base *big.Int, e *big.Int) *big.Int {
	res := big.NewInt(1)
	rem := new(big.Int).Set(e)
	exp := base

	for !bytes.Equal(rem.Bytes(), big.NewInt(int64(0)).Bytes()) {
		// if BigIsOdd(rem) {
		if rem.Bit(0) == 1 { // .Bit(0) returns 1 when is odd
			res = fMul(res, exp)
		}
		exp = fMul(exp, exp)
		rem = new(big.Int).Rsh(rem, 1)
	}
	return res
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func polynomialSub(a, b []*big.Int) []*big.Int {
	r := arrayOfZeroes(max(len(a), len(b)))
	for i := 0; i < len(a); i++ {
		r[i] = fAdd(r[i], a[i])
	}
	for i := 0; i < len(b); i++ {
		r[i] = fSub(r[i], b[i])
	}
	return r
}

func polynomialMul(a, b []*big.Int) []*big.Int {
	r := arrayOfZeroes(len(a) + len(b) - 1)
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			r[i+j] = fAdd(r[i+j], fMul(a[i], b[j]))
		}
	}
	return r
}

func polynomialDiv(a, b []*big.Int) ([]*big.Int, []*big.Int) {
	// https://en.wikipedia.org/wiki/Division_algorithm
	r := arrayOfZeroes(len(a) - len(b) + 1)
	rem := a
	for len(rem) >= len(b) {
		l := fDiv(rem[len(rem)-1], b[len(b)-1])
		pos := len(rem) - len(b)
		r[pos] = l
		aux := arrayOfZeroes(pos)
		aux1 := append(aux, l)
		aux2 := polynomialSub(rem, polynomialMul(b, aux1))
		rem = aux2[:len(aux2)-1]
	}
	return r, rem
}
