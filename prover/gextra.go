package prover

import (
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	cryptoConstants "github.com/iden3/go-iden3-crypto/constants"
)

type tableG1 struct {
	data []*bn256.G1
}

func (t tableG1) getData() []*bn256.G1 {
	return t.data
}

// Compute table of gsize elements as ::
//  Table[0] = Inf
//  Table[1] = a[0]
//  Table[2] = a[1]
//  Table[3] = a[0]+a[1]
//  .....
//  Table[(1<<gsize)-1] = a[0]+a[1]+...+a[gsize-1]
func (t *tableG1) newTableG1(a []*bn256.G1, gsize int, toaffine bool) {
	// EC table
	table := make([]*bn256.G1, 0)

	// We need at least gsize elements. If not enough, fill with 0
	aExt := make([]*bn256.G1, 0)
	aExt = append(aExt, a...)

	for i := len(a); i < gsize; i++ {
		aExt = append(aExt, new(bn256.G1).ScalarBaseMult(big.NewInt(0)))
	}

	elG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	table = append(table, elG1)
	lastPow2 := 1
	nelems := 0
	for i := 1; i < 1<<gsize; i++ {
		elG1 := new(bn256.G1)
		// if power of 2
		if i&(i-1) == 0 {
			lastPow2 = i
			elG1.Set(aExt[nelems])
			nelems++
		} else {
			elG1.Add(table[lastPow2], table[i-lastPow2])
			// TODO bn256 doesn't export MakeAffine function. We need to fork repo
			//table[i].MakeAffine()
		}
		table = append(table, elG1)
	}
	if toaffine {
		for i := 0; i < len(table); i++ {
			info := table[i].Marshal()
			table[i].Unmarshal(info)
		}
	}
	t.data = table
}

func (t tableG1) Marshal() []byte {
	info := make([]byte, 0)
	for _, el := range t.data {
		info = append(info, el.Marshal()...)
	}

	return info
}

// Multiply scalar by precomputed table of G1 elements
func (t *tableG1) mulTableG1(k []*big.Int, qPrev *bn256.G1, gsize int) *bn256.G1 {
	// We need at least gsize elements. If not enough, fill with 0
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)

	for i := len(k); i < gsize; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}

	Q := new(bn256.G1).ScalarBaseMult(big.NewInt(0))

	msb := getMsb(kExt)

	for i := msb - 1; i >= 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		Q = new(bn256.G1).Add(Q, Q)
		b := getBit(kExt, i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q.Add(Q, t.data[b])
		}
	}
	if qPrev != nil {
		return Q.Add(Q, qPrev)
	}
	return Q
}

// Multiply scalar by precomputed table of G1 elements without intermediate doubling
func mulTableNoDoubleG1(t []tableG1, k []*big.Int, qPrev *bn256.G1, gsize int) *bn256.G1 {
	// We need at least gsize elements. If not enough, fill with 0
	minNElems := len(t) * gsize
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)
	for i := len(k); i < minNElems; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*bn256.G1, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < len(t); j++ {
		msb := getMsb(kExt[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(kExt[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], t[j].data[b])
			}
		}
	}

	// Consolidate Addition
	R := new(bn256.G1).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(bn256.G1).Add(R, R)
		R.Add(R, Q[i-1])
	}

	if qPrev != nil {
		return R.Add(R, qPrev)
	}
	return R
}

// Compute tables within function. This solution should still be faster than std  multiplication
// for gsize = 7
func scalarMultG1(a []*bn256.G1, k []*big.Int, qPrev *bn256.G1, gsize int) *bn256.G1 {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := tableG1{}
	Q := new(bn256.G1).ScalarBaseMult(new(big.Int))

	for i := 0; i < ntables-1; i++ {
		table.newTableG1(a[i*gsize:(i+1)*gsize], gsize, false)
		Q = table.mulTableG1(k[i*gsize:(i+1)*gsize], Q, gsize)
	}
	table.newTableG1(a[(ntables-1)*gsize:], gsize, false)
	Q = table.mulTableG1(k[(ntables-1)*gsize:], Q, gsize)

	if qPrev != nil {
		return Q.Add(Q, qPrev)
	}
	return Q
}

// Multiply scalar by precomputed table of G1 elements without intermediate doubling
func scalarMultNoDoubleG1(a []*bn256.G1, k []*big.Int, qPrev *bn256.G1, gsize int) *bn256.G1 {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := tableG1{}

	// We need at least gsize elements. If not enough, fill with 0
	minNElems := ntables * gsize
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)
	for i := len(k); i < minNElems; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*bn256.G1, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < ntables-1; j++ {
		table.newTableG1(a[j*gsize:(j+1)*gsize], gsize, false)
		msb := getMsb(kExt[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(kExt[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], table.data[b])
			}
		}
	}
	table.newTableG1(a[(ntables-1)*gsize:], gsize, false)
	msb := getMsb(kExt[(ntables-1)*gsize:])

	for i := msb - 1; i >= 0; i-- {
		b := getBit(kExt[(ntables-1)*gsize:], i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q[i].Add(Q[i], table.data[b])
		}
	}

	// Consolidate Addition
	R := new(bn256.G1).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(bn256.G1).Add(R, R)
		R.Add(R, Q[i-1])
	}
	if qPrev != nil {
		return R.Add(R, qPrev)
	}
	return R
}

/////

// TODO - How can avoid replicating code in G2?
//G2

type tableG2 struct {
	data []*bn256.G2
}

func (t tableG2) getData() []*bn256.G2 {
	return t.data
}

// Compute table of gsize elements as ::
//  Table[0] = Inf
//  Table[1] = a[0]
//  Table[2] = a[1]
//  Table[3] = a[0]+a[1]
//  .....
//  Table[(1<<gsize)-1] = a[0]+a[1]+...+a[gsize-1]
// TODO -> toaffine = True doesnt work. Problem with Marshal/Unmarshal
func (t *tableG2) newTableG2(a []*bn256.G2, gsize int, toaffine bool) {
	// EC table
	table := make([]*bn256.G2, 0)

	// We need at least gsize elements. If not enough, fill with 0
	aExt := make([]*bn256.G2, 0)
	aExt = append(aExt, a...)

	for i := len(a); i < gsize; i++ {
		aExt = append(aExt, new(bn256.G2).ScalarBaseMult(big.NewInt(0)))
	}

	elG2 := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	table = append(table, elG2)
	lastPow2 := 1
	nelems := 0
	for i := 1; i < 1<<gsize; i++ {
		elG2 := new(bn256.G2)
		// if power of 2
		if i&(i-1) == 0 {
			lastPow2 = i
			elG2.Set(aExt[nelems])
			nelems++
		} else {
			elG2.Add(table[lastPow2], table[i-lastPow2])
			// TODO bn256 doesn't export MakeAffine function. We need to fork repo
			//table[i].MakeAffine()
		}
		table = append(table, elG2)
	}
	if toaffine {
		for i := 0; i < len(table); i++ {
			info := table[i].Marshal()
			table[i].Unmarshal(info)
		}
	}
	t.data = table
}

func (t tableG2) Marshal() []byte {
	info := make([]byte, 0)
	for _, el := range t.data {
		info = append(info, el.Marshal()...)
	}

	return info
}

// Multiply scalar by precomputed table of G2 elements
func (t *tableG2) mulTableG2(k []*big.Int, qPrev *bn256.G2, gsize int) *bn256.G2 {
	// We need at least gsize elements. If not enough, fill with 0
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)

	for i := len(k); i < gsize; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}

	Q := new(bn256.G2).ScalarBaseMult(big.NewInt(0))

	msb := getMsb(kExt)

	for i := msb - 1; i >= 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		Q = new(bn256.G2).Add(Q, Q)
		b := getBit(kExt, i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q.Add(Q, t.data[b])
		}
	}
	if qPrev != nil {
		return Q.Add(Q, qPrev)
	}
	return Q
}

// Multiply scalar by precomputed table of G2 elements without intermediate doubling
func mulTableNoDoubleG2(t []tableG2, k []*big.Int, qPrev *bn256.G2, gsize int) *bn256.G2 {
	// We need at least gsize elements. If not enough, fill with 0
	minNElems := len(t) * gsize
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)
	for i := len(k); i < minNElems; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*bn256.G2, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < len(t); j++ {
		msb := getMsb(kExt[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(kExt[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], t[j].data[b])
			}
		}
	}

	// Consolidate Addition
	R := new(bn256.G2).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(bn256.G2).Add(R, R)
		R.Add(R, Q[i-1])
	}
	if qPrev != nil {
		return R.Add(R, qPrev)
	}
	return R
}

// Compute tables within function. This solution should still be faster than std  multiplication
// for gsize = 7
func scalarMultG2(a []*bn256.G2, k []*big.Int, qPrev *bn256.G2, gsize int) *bn256.G2 {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := tableG2{}
	Q := new(bn256.G2).ScalarBaseMult(new(big.Int))

	for i := 0; i < ntables-1; i++ {
		table.newTableG2(a[i*gsize:(i+1)*gsize], gsize, false)
		Q = table.mulTableG2(k[i*gsize:(i+1)*gsize], Q, gsize)
	}
	table.newTableG2(a[(ntables-1)*gsize:], gsize, false)
	Q = table.mulTableG2(k[(ntables-1)*gsize:], Q, gsize)

	if qPrev != nil {
		return Q.Add(Q, qPrev)
	}
	return Q
}

// Multiply scalar by precomputed table of G2 elements without intermediate doubling
func scalarMultNoDoubleG2(a []*bn256.G2, k []*big.Int, qPrev *bn256.G2, gsize int) *bn256.G2 {
	ntables := int((len(a) + gsize - 1) / gsize)
	table := tableG2{}

	// We need at least gsize elements. If not enough, fill with 0
	minNElems := ntables * gsize
	kExt := make([]*big.Int, 0)
	kExt = append(kExt, k...)
	for i := len(k); i < minNElems; i++ {
		kExt = append(kExt, new(big.Int).SetUint64(0))
	}
	// Init Adders
	nbitsQ := cryptoConstants.Q.BitLen()
	Q := make([]*bn256.G2, nbitsQ)

	for i := 0; i < nbitsQ; i++ {
		Q[i] = new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	}

	// Perform bitwise addition
	for j := 0; j < ntables-1; j++ {
		table.newTableG2(a[j*gsize:(j+1)*gsize], gsize, false)
		msb := getMsb(kExt[j*gsize : (j+1)*gsize])

		for i := msb - 1; i >= 0; i-- {
			b := getBit(kExt[j*gsize:(j+1)*gsize], i)
			if b != 0 {
				// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
				Q[i].Add(Q[i], table.data[b])
			}
		}
	}
	table.newTableG2(a[(ntables-1)*gsize:], gsize, false)
	msb := getMsb(kExt[(ntables-1)*gsize:])

	for i := msb - 1; i >= 0; i-- {
		b := getBit(kExt[(ntables-1)*gsize:], i)
		if b != 0 {
			// TODO. bn256 doesn't export mixed addition (Jacobian + Affine), which is more efficient.
			Q[i].Add(Q[i], table.data[b])
		}
	}

	// Consolidate Addition
	R := new(bn256.G2).Set(Q[nbitsQ-1])
	for i := nbitsQ - 1; i > 0; i-- {
		// TODO. bn256 doesn't export double operation. We will need to fork repo and export it
		R = new(bn256.G2).Add(R, R)
		R.Add(R, Q[i-1])
	}
	if qPrev != nil {
		return R.Add(R, qPrev)
	}
	return R
}

// Return most significant bit position in a group of Big Integers
func getMsb(k []*big.Int) int {
	msb := 0

	for _, el := range k {
		tmpMsb := el.BitLen()
		if tmpMsb > msb {
			msb = tmpMsb
		}
	}
	return msb
}

// Return ith bit in group of Big Integers
func getBit(k []*big.Int, i int) uint {
	tableIdx := uint(0)

	for idx, el := range k {
		b := el.Bit(i)
		tableIdx += (b << idx)
	}
	return tableIdx
}
