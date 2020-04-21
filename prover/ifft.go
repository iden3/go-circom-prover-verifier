package prover

import (
	"math"
	"math/big"

	"github.com/iden3/go-circom-prover-verifier/types"
	"github.com/iden3/go-iden3-crypto/ff"
)

type rootsT struct {
	roots [][]*ff.Element
	w     []*ff.Element
}

func newRootsT() rootsT {
	var roots rootsT

	rem := new(big.Int).Sub(types.R, big.NewInt(1))
	s := 0
	for rem.Bit(0) == 0 { // rem.Bit==0 when even
		s++
		rem = new(big.Int).Rsh(rem, 1)
	}
	roots.w = make([]*ff.Element, s+1)
	roots.w[s] = ff.NewElement().SetBigInt(fExp(big.NewInt(5), rem))

	n := s - 1
	for n >= 0 {
		roots.w[n] = ff.NewElement().Mul(roots.w[n+1], roots.w[n+1])
		n--
	}
	roots.roots = make([][]*ff.Element, 50) // TODO WIP

	roots.setRoots(15)
	return roots
}

func (roots rootsT) setRoots(n int) {
	for i := n; i >= 0 && nil == roots.roots[i]; i-- { // TODO tmp i<=len(r)
		r := ff.NewElement().SetBigInt(big.NewInt(1))
		nroots := 1 << i
		var rootsi []*ff.Element
		for j := 0; j < nroots; j++ {
			rootsi = append(rootsi, r)
			r = ff.NewElement().Mul(r, roots.w[i])
		}
		roots.roots[i] = rootsi
	}
}

func fftroots(roots rootsT, pall []*ff.Element, bits, offset, step int) []*ff.Element {
	n := 1 << bits
	if n == 1 {
		return []*ff.Element{pall[offset]}
	} else if n == 2 {
		return []*ff.Element{
			ff.NewElement().Add(pall[offset], pall[offset+step]), // TODO tmp
			ff.NewElement().Sub(pall[offset], pall[offset+step]),
		}
	}

	ndiv2 := n >> 1
	p1 := fftroots(roots, pall, bits-1, offset, step*2)
	p2 := fftroots(roots, pall, bits-1, offset+step, step*2)

	out := make([]*ff.Element, n)
	for i := 0; i < ndiv2; i++ {
		out[i] = ff.NewElement().Add(p1[i], ff.NewElement().Mul(roots.roots[bits][i], p2[i]))
		out[i+ndiv2] = ff.NewElement().Sub(p1[i], ff.NewElement().Mul(roots.roots[bits][i], p2[i]))
	}
	return out
}

func fft(p []*ff.Element) []*ff.Element {
	if len(p) <= 1 {
		return p
	}
	bits := math.Log2(float64(len(p)-1)) + 1
	roots := newRootsT()
	roots.setRoots(int(bits))
	m := 1 << int(bits)
	ep := extend(p, m)
	res := fftroots(roots, ep, int(bits), 0, 1)
	return res
}

func ifft(p []*ff.Element) []*ff.Element {
	res := fft(p)
	bits := math.Log2(float64(len(p)-1)) + 1
	m := 1 << int(bits)

	twoinvm := ff.NewElement().SetBigInt(fInv(fMul(big.NewInt(1), big.NewInt(int64(m)))))

	var resn []*ff.Element
	for i := 0; i < m; i++ {
		resn = append(resn, ff.NewElement().Mul(res[(m-i)%m], twoinvm))
	}

	return resn
}

func extend(p []*ff.Element, e int) []*ff.Element {
	if e == len(p) {
		return p
	}
	z := arrayOfZeroesE(e - len(p))
	return append(p, z...)
}
