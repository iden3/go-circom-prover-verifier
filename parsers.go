package gocircomprover

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

type ProvingKeyString struct {
	A          [][]string          `json:"A"`
	B2         [][][]string        `json:"B2"`
	B1         [][]string          `json:"B1"`
	C          [][]string          `json:"C"`
	NVars      int                 `json:"nVars"`
	NPublic    int                 `json:"nPublic"`
	VkAlpha1   []string            `json:"vk_alfa_1"`
	VkDelta1   []string            `json:"vk_delta_1"`
	VkBeta1    []string            `json:"vk_beta_1"`
	VkBeta2    [][]string          `json:"vk_beta_2"`
	VkDelta2   [][]string          `json:"vk_delta_2"`
	HExps      [][]string          `json:"hExps"`
	DomainSize int                 `json:"domainSize"`
	PolsA      []map[string]string `json:"polsA"`
	PolsB      []map[string]string `json:"polsB"`
	PolsC      []map[string]string `json:"polsC"`
}

type WitnessString []string

func ParseProvingKey(pkJson []byte) (*ProvingKey, error) {
	var pkStr ProvingKeyString
	err := json.Unmarshal(pkJson, &pkStr)
	if err != nil {
		return nil, err
	}
	pk, err := provingKeyStringToProvingKey(pkStr)
	return pk, err
}

func provingKeyStringToProvingKey(ps ProvingKeyString) (*ProvingKey, error) {
	var p ProvingKey
	var err error

	p.A, err = arrayStringToG1(ps.A)
	if err != nil {
		return nil, err
	}
	p.B2, err = arrayStringToG2(ps.B2)
	if err != nil {
		return nil, err
	}
	p.B1, err = arrayStringToG1(ps.B1)
	if err != nil {
		return nil, err
	}
	p.C, err = arrayStringToG1(ps.C)
	if err != nil {
		return nil, err
	}

	p.NVars = ps.NVars
	p.NPublic = ps.NPublic

	p.VkAlpha1, err = stringToG1(ps.VkAlpha1)
	if err != nil {
		return nil, err
	}

	p.VkDelta1, err = stringToG1(ps.VkDelta1)
	if err != nil {
		return nil, err
	}

	p.VkBeta1, err = stringToG1(ps.VkBeta1)
	if err != nil {
		return nil, err
	}
	p.VkBeta2, err = stringToG2(ps.VkBeta2)
	if err != nil {
		return nil, err
	}
	p.VkDelta2, err = stringToG2(ps.VkDelta2)
	if err != nil {
		return nil, err
	}

	p.HExps, err = arrayStringToG1(ps.HExps)
	if err != nil {
		return nil, err
	}

	p.DomainSize = ps.DomainSize

	p.PolsA, err = polsStringToBigInt(ps.PolsA)
	if err != nil {
		return nil, err
	}
	p.PolsB, err = polsStringToBigInt(ps.PolsB)
	if err != nil {
		return nil, err
	}
	p.PolsC, err = polsStringToBigInt(ps.PolsC)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

// polsStringToBigInt is for taking string polynomials and converting it to *big.Int polynomials
func polsStringToBigInt(s []map[string]string) ([]map[int]*big.Int, error) {
	var o []map[int]*big.Int
	for i := 0; i < len(s); i++ {
		// var oi map[int]*big.Int
		oi := make(map[int]*big.Int)
		for j, v := range s[i] {
			si, err := stringToBigInt(v)
			if err != nil {
				return o, err
			}
			// oi = append(oi, si)
			jInt, err := strconv.Atoi(j)
			if err != nil {
				fmt.Println(j)
				return o, err
			}
			fmt.Println(jInt, si)
			oi[jInt] = si
		}
		o = append(o, oi)
	}
	return o, nil
}

func arrayStringToBigInt(s []string) ([]*big.Int, error) {
	var o []*big.Int
	for i := 0; i < len(s); i++ {
		si, err := stringToBigInt(s[i])
		if err != nil {
			return o, nil
		}
		o = append(o, si)
	}
	return o, nil
}

func stringToBigInt(s string) (*big.Int, error) {
	base := 10
	if bytes.HasPrefix([]byte(s), []byte("0x")) {
		base = 16
		s = strings.TrimPrefix(s, "0x")
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, fmt.Errorf("Can not parse string to *big.Int: %s", s)
	}
	return n, nil
}

func addZPadding(b []byte) []byte {
	var z [32]byte
	var r []byte
	r = append(r, z[len(b):]...) // add padding on the left
	r = append(r, b...)
	return r[:32]
}

func stringToBytes(s string) ([]byte, error) {
	if s == "1" {
		s = "0"
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("error parsing bigint stringToBytes")
	}
	b := bi.Bytes()
	if len(b) != 32 {
		b = addZPadding(b)
	}
	return b, nil

}

func arrayStringToG1(h [][]string) ([]*bn256.G1, error) {
	var o []*bn256.G1
	for i := 0; i < len(h); i++ {
		hi, err := stringToG1(h[i])
		if err != nil {
			return o, err
		}
		o = append(o, hi)
	}
	return o, nil
}

func arrayStringToG2(h [][][]string) ([]*bn256.G2, error) {
	var o []*bn256.G2
	for i := 0; i < len(h); i++ {
		hi, err := stringToG2(h[i])
		if err != nil {
			return o, err
		}
		o = append(o, hi)
	}
	return o, nil
}

func stringToG1(h []string) (*bn256.G1, error) {
	if len(h) <= 2 {
		return nil, fmt.Errorf("not enought data for stringToG1")
	}
	h = h[:2]
	hexa := false
	if len(h[0]) > 1 {
		if "0x" == h[0][:2] {
			hexa = true
		}
	}
	in := ""

	var b []byte
	var err error
	if hexa {
		for i := range h {
			in += strings.TrimPrefix(h[i], "0x")
		}
		b, err = hex.DecodeString(in)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO TMP
		// TODO use stringToBytes()
		if h[0] == "1" {
			h[0] = "0"
		}
		if h[1] == "1" {
			h[1] = "0"
		}
		bi0, ok := new(big.Int).SetString(h[0], 10)
		if !ok {
			return nil, fmt.Errorf("error parsing stringToG1")
		}
		bi1, ok := new(big.Int).SetString(h[1], 10)
		if !ok {
			return nil, fmt.Errorf("error parsing stringToG1")
		}
		b0 := bi0.Bytes()
		b1 := bi1.Bytes()
		if len(b0) != 32 {
			b0 = addZPadding(b0)
		}
		if len(b1) != 32 {
			b1 = addZPadding(b1)
		}

		b = append(b, b0...)
		b = append(b, b1...)
	}
	p := new(bn256.G1)
	_, err = p.Unmarshal(b)

	return p, err
}

func stringToG2(h [][]string) (*bn256.G2, error) {
	if len(h) <= 2 {
		return nil, fmt.Errorf("not enought data for stringToG2")
	}
	h = h[:2]
	hexa := false
	if len(h[0][0]) > 1 {
		if "0x" == h[0][0][:2] {
			hexa = true
		}
	}
	in := ""
	var b []byte
	var err error
	if hexa {
		for i := 0; i < len(h); i++ {
			for j := 0; j < len(h[i]); j++ {
				in += strings.TrimPrefix(h[i][j], "0x")
			}
		}
		b, err = hex.DecodeString(in)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO TMP
		bH, err := stringToBytes(h[0][1])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[0][0])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[1][1])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[1][0])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
	}

	p := new(bn256.G2)
	_, err = p.Unmarshal(b)
	return p, err
}
