package prover

import (
	"crypto/rand"
	"math/big"
	"testing"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
        "time"
        "bytes"
        "fmt"
)

const (
       N = 5000
)

func randomBigIntArray(n int) []*big.Int{
	var p []*big.Int
	for i := 0; i < n; i++ {
		pi := randBI()
		p = append(p, pi)
	}

        return p
}

func randomG1Array(n int) []*bn256.G1 {
     arrayG1 := make([]*bn256.G1, n)

     for i:=0; i<n; i++ {
       _, arrayG1[i], _ = bn256.RandomG1(rand.Reader)
     }
     return arrayG1
}


func TestTable(t *testing.T){
     n     := N

     // init scalar
     var arrayW = randomBigIntArray(N)
     // init G1 array
     var arrayG1 = randomG1Array(N)

     beforeT := time.Now()
     Q1 := new(bn256.G1).ScalarBaseMult(new(big.Int))
     for i:=0; i < n; i++ {
         Q1.Add(Q1, new(bn256.G1).ScalarMult(arrayG1[i], arrayW[i]))
     }
     fmt.Println("Std. Mult. time elapsed:", time.Since(beforeT))
   
     for gsize:=2; gsize < 10; gsize++ {
        ntables := int((n + gsize - 1) / gsize)
        table := make([]TableG1, ntables)
   
        for i:=0; i<ntables-1; i++ {
          table[i].NewTableG1( arrayG1[i*gsize:(i+1)*gsize], gsize)
        }
        table[ntables-1].NewTableG1( arrayG1[(ntables-1)*gsize:], gsize)
   
        beforeT = time.Now()
        Q2:= new(bn256.G1).ScalarBaseMult(new(big.Int))
        for i:=0; i<ntables-1; i++ {
           Q2.Add(Q2,table[i].MulTableG1(arrayW[i*gsize:(i+1)*gsize], gsize))
        }
        Q2.Add(Q2,table[ntables-1].MulTableG1(arrayW[(ntables-1)*gsize:], gsize))
        fmt.Printf("Gsize : %d, TMult time elapsed: %s\n", gsize,time.Since(beforeT))
   
        beforeT = time.Now()
        Q3 := ScalarMult(arrayG1, arrayW, gsize)
        fmt.Printf("Gsize : %d, TMult time elapsed (inc table comp): %s\n", gsize,time.Since(beforeT))

        beforeT = time.Now()
        Q4 := MulTableNoDoubleG1(table, arrayW, gsize)
        fmt.Printf("Gsize : %d, TMultNoDouble time elapsed: %s\n", gsize,time.Since(beforeT))

        beforeT = time.Now()
        Q5 := ScalarMultNoDoubleG1(arrayG1, arrayW, gsize)
        fmt.Printf("Gsize : %d, TMultNoDouble time elapsed (inc table comp): %s\n", gsize,time.Since(beforeT))
   
   
   
        if bytes.Compare(Q1.Marshal(),Q2.Marshal()) != 0 {
            t.Error("Error in TMult")
        }
        if bytes.Compare(Q1.Marshal(),Q3.Marshal()) != 0 {
            t.Error("Error in  TMult with table comp")
        }
        if bytes.Compare(Q1.Marshal(),Q4.Marshal()) != 0 {
            t.Error("Error in  TMultNoDouble")
        }
        if bytes.Compare(Q1.Marshal(),Q5.Marshal()) != 0 {
            t.Error("Error in  TMultNoDoublee with table comp")
        }
    }
}
