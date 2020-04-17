package prover

import (
	"math"
	"math/big"
)

type rootsT struct {
	roots [][]*big.Int
	w     []*big.Int
}

func newRootsT() rootsT {
	var roots rootsT

	rem := new(big.Int).Sub(R, big.NewInt(1))
	s := 0
	for rem.Bit(0) == 0 { // rem.Bit==0 when even
		s++
		rem = new(big.Int).Rsh(rem, 1)
	}
	roots.w = make([]*big.Int, s+1)
	roots.w[s] = fExp(big.NewInt(5), rem)

	n := s - 1
	for n >= 0 {
		roots.w[n] = fMul(roots.w[n+1], roots.w[n+1])
		n--
	}
	roots.roots = make([][]*big.Int, 50) // TODO WIP

	roots.setRoots(15)
	return roots
}

func (roots rootsT) setRoots(n int) {
	for i := n; i >= 0 && nil == roots.roots[i]; i-- { // TODO tmp i<=len(r)
		r := big.NewInt(1)
		nroots := 1 << i
		var rootsi []*big.Int
		for j := 0; j < nroots; j++ {
			rootsi = append(rootsi, r)
			r = fMul(r, roots.w[i])
		}
		roots.roots[i] = rootsi
	}
}

func fft(roots rootsT, pall []*big.Int, bits, offset, step int) []*big.Int {
	n := 1 << bits
	if n == 1 {
		return []*big.Int{pall[offset]}
	} else if n == 2 {
		return []*big.Int{
			fAdd(pall[offset], pall[offset+step]), // TODO tmp
			fSub(pall[offset], pall[offset+step]),
		}
	}

	ndiv2 := n >> 1
	p1 := fft(roots, pall, bits-1, offset, step*2)
	p2 := fft(roots, pall, bits-1, offset+step, step*2)

	// var out []*big.Int
	out := make([]*big.Int, n)
	for i := 0; i < ndiv2; i++ {
		// fmt.Println(i, len(roots.roots))
		out[i] = fAdd(p1[i], fMul(roots.roots[bits][i], p2[i]))
		out[i+ndiv2] = fSub(p1[i], fMul(roots.roots[bits][i], p2[i]))
	}
	return out
}

func ifft(p []*big.Int) []*big.Int {
	if len(p) <= 1 {
		return p
	}
	bits := math.Log2(float64(len(p)-1)) + 1
	roots := newRootsT()
	roots.setRoots(int(bits))
	m := 1 << int(bits)
	ep := extend(p, m)
	res := fft(roots, ep, int(bits), 0, 1)

	twoinvm := fInv(fMul(big.NewInt(1), big.NewInt(int64(m))))

	var resn []*big.Int
	for i := 0; i < m; i++ {
		resn = append(resn, fMul(res[(m-i)%m], twoinvm))
	}

	return resn
}

func extend(p []*big.Int, e int) []*big.Int {
	if e == len(p) {
		return p
	}
	z := arrayOfZeroes(e - len(p))
	return append(p, z...)
}
