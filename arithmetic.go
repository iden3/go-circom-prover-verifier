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

func FAdd(a, b *big.Int) *big.Int {
	ab := new(big.Int).Add(a, b)
	return new(big.Int).Mod(ab, R)
}

func FSub(a, b *big.Int) *big.Int {
	ab := new(big.Int).Sub(a, b)
	return new(big.Int).Mod(ab, R)
}

func FMul(a, b *big.Int) *big.Int {
	ab := new(big.Int).Mul(a, b)
	return new(big.Int).Mod(ab, R)
}

func FDiv(a, b *big.Int) *big.Int {
	ab := new(big.Int).Mul(a, new(big.Int).ModInverse(b, R))
	return new(big.Int).Mod(ab, R)
}

func FNeg(a *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Neg(a), R)
}

func FInv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, R)
}

func FExp(base *big.Int, e *big.Int) *big.Int {
	res := big.NewInt(1)
	rem := new(big.Int).Set(e)
	exp := base

	for !bytes.Equal(rem.Bytes(), big.NewInt(int64(0)).Bytes()) {
		// if BigIsOdd(rem) {
		if rem.Bit(0) == 1 { // .Bit(0) returns 1 when is odd
			res = FMul(res, exp)
		}
		exp = FMul(exp, exp)
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

func PolynomialSub(a, b []*big.Int) []*big.Int {
	r := arrayOfZeroes(max(len(a), len(b)))
	for i := 0; i < len(a); i++ {
		r[i] = FAdd(r[i], a[i])
	}
	for i := 0; i < len(b); i++ {
		r[i] = FSub(r[i], b[i])
	}
	return r
}

func PolynomialMul(a, b []*big.Int) []*big.Int {
	r := arrayOfZeroes(len(a) + len(b) - 1)
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			r[i+j] = FAdd(r[i+j], FMul(a[i], b[j]))
		}
	}
	return r
}

func PolynomialDiv(a, b []*big.Int) ([]*big.Int, []*big.Int) {
	// https://en.wikipedia.org/wiki/Division_algorithm
	r := arrayOfZeroes(len(a) - len(b) + 1)
	rem := a
	for len(rem) >= len(b) {
		l := FDiv(rem[len(rem)-1], b[len(b)-1])
		pos := len(rem) - len(b)
		r[pos] = l
		aux := arrayOfZeroes(pos)
		aux1 := append(aux, l)
		aux2 := PolynomialSub(rem, PolynomialMul(b, aux1))
		rem = aux2[:len(aux2)-1]
	}
	return r, rem
}
