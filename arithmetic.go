package gocircomprover

import (
	"bytes"
	"math/big"
)

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
