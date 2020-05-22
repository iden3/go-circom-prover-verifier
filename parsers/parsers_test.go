package parsers

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/iden3/go-circom-prover-verifier/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArrayG1(t *testing.T) {
	aS := [][]string{
		{
			"16145916318196730299582072104388453231952213805668281741813587224450782397538",
			"4434505318477484327659527264104806919103674231447634885054368605283938696207",
			"1",
		},
		{
			"10618406967550056457559358662746625591602641004174976323307214433994084907915",
			"1843236360452735081347085412539192450068665510574800388201121698908391533923",
			"1",
		},
		{
			"1208972877970123411566574123860641832032384890981476033353526096830198333194",
			"777503551507025252294438107100944741641946695980350712141258191590862204805",
			"1",
		},
		{
			"0",
			"1",
			"0",
		},
	}

	a, err := arrayStringToG1(aS)
	assert.Nil(t, err)
	assert.Equal(t, "bn256.G1(23b243c928ce40c4cc2dad366e9f61723aef65866e1c66f42a08697f2f030462, 09cdd7500688fb487ec9f27b5a732d68fa0f3ddca5c2c790e330fdfb03b77c0f)", a[0].String())
	assert.Equal(t, "bn256.G1(1779ce2c586b5fc523e72e755d969a63473052aaad7c11eb5bf0ecdcfdfefb8b, 04133c1c74206dace57cd3d76ce59be381bbf08f51a5b3edc2b0c183d43eed63)", a[1].String())
	assert.Equal(t, "bn256.G1(02ac4120598d2f2bb81bc09b8df596403360577b0c5ff52485d1ef2200f23f0a, 01b80d298de75f867d6484c55c3da02c042bb4eb9a1734d3386786aaa669af85)", a[2].String())
	assert.Equal(t, "bn256.G1(0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000001)", a[3].String())
}

func TestParseG2(t *testing.T) {
	aS := [][]string{
		{
			"9283666785342556550467669770956850930982548182701254051508520248901282197973",
			"11369378229277445316894458966429873744779877313900506577160370623273013178252",
		},
		{
			"10625777544326349817513295021482494426101347915428005055375725845993157551870",
			"21401790227434807639472120486932615400751346915707967674912972446672152512583",
		},
		{
			"1",
			"0",
		},
	}

	a, err := stringToG2(aS)
	assert.Nil(t, err)
	assert.Equal(t, "bn256.G2((1922d70c934543aa655ec3277f7fa10a25ec973a4f001a7c54ce4954b4916f8c, 14865e836947c42cf35b47d30e06535fff9dab319c4296e28afde368960671d5), (2f50fbe77925b0a9d718c9ab38638bafa7c65f43f0d09035e518df97ad294847, 177dfa1a3b8627faf0425d9511bcb4c6ca986ea05e3803b5c643c35b94a7e6fe))", a.String())

	aS = [][]string{
		{
			"13973091636763944887728510851169742544309374663995476311690518173988838518856",
			"12903946180439304546475897520537621821375470264150438270817301786763517825250",
		},
		{
			"370374369234123593044872519351942112043402224488849374153134091815693350697",
			"17423079115073430837335625309232513526393852743032331213038909731579295753224",
		},
		{
			"1",
			"0",
		},
	}
	a, err = stringToG2(aS)
	assert.Nil(t, err)
	assert.Equal(t, "bn256.G2((1c875fed67fff3b35f115b03706ec45f281b5f6cc71a99107240e09fce4910e2, 1ee47d566e9a099626b9860bcd96f6d4a1ed65f115d3efa8e05e5f42cc793048), (26851d022ce9961df65a430811824aaf3118710ac03b0614a50c05ee27d8e408, 00d19fdce25b0d78fb317a5f1789823b7ed76274b0d1be9c685792c73b347729))", a.String())
}

func TestParseArrayG2(t *testing.T) {
	aS := [][][]string{
		{
			{
				"0",
				"0",
			},
			{
				"1",
				"0",
			},
			{
				"0",
				"0",
			},
		},
		{
			{
				"0",
				"0",
			},
			{
				"1",
				"0",
			},
			{
				"0",
				"0",
			},
		},
		{
			{
				"0",
				"0",
			},
			{
				"1",
				"0",
			},
			{
				"0",
				"0",
			},
		},
		{
			{
				"9283666785342556550467669770956850930982548182701254051508520248901282197973",
				"11369378229277445316894458966429873744779877313900506577160370623273013178252",
			},
			{
				"10625777544326349817513295021482494426101347915428005055375725845993157551870",
				"21401790227434807639472120486932615400751346915707967674912972446672152512583",
			},
			{
				"1",
				"0",
			},
		},
	}

	a, err := arrayStringToG2(aS)
	assert.Nil(t, err)
	assert.Equal(t, "bn256.G2((0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000000), (0000000000000000000000000000000000000000000000000000000000000000, 0000000000000000000000000000000000000000000000000000000000000001))", a[0].String())
	assert.Equal(t, "bn256.G2((1922d70c934543aa655ec3277f7fa10a25ec973a4f001a7c54ce4954b4916f8c, 14865e836947c42cf35b47d30e06535fff9dab319c4296e28afde368960671d5), (2f50fbe77925b0a9d718c9ab38638bafa7c65f43f0d09035e518df97ad294847, 177dfa1a3b8627faf0425d9511bcb4c6ca986ea05e3803b5c643c35b94a7e6fe))", a[3].String())

}

func testCircuitParseWitnessBin(t *testing.T, circuit string) {
	witnessBinFile, err := os.Open("../testdata/" + circuit + "/witness.bin")
	require.Nil(t, err)
	defer witnessBinFile.Close()
	witness, err := ParseWitnessBin(witnessBinFile)
	require.Nil(t, err)

	witnessJson, err := ioutil.ReadFile("../testdata/" + circuit + "/witness.json")
	require.Nil(t, err)
	w, err := ParseWitness(witnessJson)
	require.Nil(t, err)

	assert.Equal(t, len(w), len(witness))
	assert.Equal(t, w[0], witness[0])
	assert.Equal(t, w[1], witness[1])
	assert.Equal(t, w[10], witness[10])
	assert.Equal(t, w[len(w)-3], witness[len(w)-3])
	assert.Equal(t, w[len(w)-2], witness[len(w)-2])
	assert.Equal(t, w[len(w)-1], witness[len(w)-1])
}

func TestParseWitnessBin(t *testing.T) {
	testCircuitParseWitnessBin(t, "circuit1k")
	testCircuitParseWitnessBin(t, "circuit5k")
}

func TestProofSmartContractFormat(t *testing.T) {
	proofJson, err := ioutil.ReadFile("../testdata/circuit1k/proof.json")
	require.Nil(t, err)
	proof, err := ParseProof(proofJson)
	require.Nil(t, err)
	pS := ProofToString(proof)

	pSC := ProofToSmartContractFormat(proof)
	assert.Nil(t, err)
	assert.Equal(t, pS.A[0], pSC.A[0])
	assert.Equal(t, pS.A[1], pSC.A[1])
	assert.Equal(t, pS.B[0][0], pSC.B[0][1])
	assert.Equal(t, pS.B[0][1], pSC.B[0][0])
	assert.Equal(t, pS.B[1][0], pSC.B[1][1])
	assert.Equal(t, pS.B[1][1], pSC.B[1][0])
	assert.Equal(t, pS.C[0], pSC.C[0])
	assert.Equal(t, pS.C[1], pSC.C[1])
	assert.Equal(t, pS.Protocol, pSC.Protocol)

	pSC2 := ProofStringToSmartContractFormat(pS)
	assert.Equal(t, pSC, pSC2)
}

func TestProofJSON(t *testing.T) {
	proofJson, err := ioutil.ReadFile("../testdata/circuit1k/proof.json")
	require.Nil(t, err)
	proof, err := ParseProof(proofJson)
	require.Nil(t, err)

	proof1JSON, err := json.Marshal(proof)
	require.Nil(t, err)
	var proof1 types.Proof
	err = json.Unmarshal(proof1JSON, &proof1)
	require.Nil(t, err)
	require.Equal(t, *proof, proof1)
}

func testCircuitParsePkBin(t *testing.T, circuit string) {
	pkBinFile, err := os.Open("../testdata/" + circuit + "/proving_key.bin")
	require.Nil(t, err)
	defer pkBinFile.Close()
	pk, err := ParsePkBin(pkBinFile)
	require.Nil(t, err)

	pkJson, err := ioutil.ReadFile("../testdata/" + circuit + "/proving_key.json")
	require.Nil(t, err)
	pkJ, err := ParsePk(pkJson)
	require.Nil(t, err)

	assert.Equal(t, pkJ.NVars, pk.NVars)
	assert.Equal(t, pkJ.NPublic, pk.NPublic)
	assert.Equal(t, pkJ.DomainSize, pk.DomainSize)
	assert.Equal(t, pkJ.VkAlpha1, pk.VkAlpha1)
	assert.Equal(t, pkJ.VkBeta1, pk.VkBeta1)
	assert.Equal(t, pkJ.VkDelta1, pk.VkDelta1)
	assert.Equal(t, pkJ.VkDelta2, pk.VkDelta2)
	assert.Equal(t, pkJ.PolsA, pk.PolsA)
	assert.Equal(t, pkJ.PolsB, pk.PolsB)
	assert.Equal(t, pkJ.A, pk.A)
	assert.Equal(t, pkJ.B1, pk.B1)
	assert.Equal(t, pkJ.B2, pk.B2)
	assert.Equal(t, pkJ.C, pk.C)
	assert.Equal(t, pkJ.HExps[:pkJ.DomainSize], pk.HExps[:pk.DomainSize]) // circom behaviour

	assert.Equal(t, pkJ.NVars, pk.NVars)
	assert.Equal(t, pkJ.NPublic, pk.NPublic)
	assert.Equal(t, pkJ.DomainSize, pk.DomainSize)
}

func TestParsePkBin(t *testing.T) {
	testCircuitParsePkBin(t, "circuit1k")
	testCircuitParsePkBin(t, "circuit5k")
}

func testGoCircomPkFormat(t *testing.T, circuit string) {
	pkJson, err := ioutil.ReadFile("../testdata/" + circuit + "/proving_key.json")
	require.Nil(t, err)
	pk, err := ParsePk(pkJson)
	require.Nil(t, err)

	pkGBin, err := PkToGoBin(pk)
	require.Nil(t, err)
	err = ioutil.WriteFile("../testdata/"+circuit+"/proving_key.go.bin", pkGBin, 0644)
	assert.Nil(t, err)

	// parse ProvingKeyGo
	pkGoBinFile, err := os.Open("../testdata/" + circuit + "/proving_key.go.bin")
	require.Nil(t, err)
	defer pkGoBinFile.Close()
	pkG, err := ParsePkGoBin(pkGoBinFile)
	require.Nil(t, err)
	assert.Equal(t, pk.VkAlpha1, pkG.VkAlpha1)
	assert.Equal(t, pk.VkBeta1, pkG.VkBeta1)
	assert.Equal(t, pk.VkDelta1, pkG.VkDelta1)
	assert.Equal(t, pk.VkBeta2, pkG.VkBeta2)
	assert.Equal(t, pk.VkDelta2, pkG.VkDelta2)
	assert.Equal(t, pk.A, pkG.A)
	assert.Equal(t, pk.B1, pkG.B1)
	assert.Equal(t, pk.B2, pkG.B2)
	assert.Equal(t, pk.C, pkG.C)
	assert.Equal(t, pk.HExps, pkG.HExps)
	assert.Equal(t, pk.PolsA, pkG.PolsA)
	assert.Equal(t, pk.PolsB, pkG.PolsB)

	assert.Equal(t, pk.NVars, pkG.NVars)
	assert.Equal(t, pk.NPublic, pkG.NPublic)
	assert.Equal(t, pk.DomainSize, pkG.DomainSize)
}

func TestGoCircomPkFormat(t *testing.T) {
	testGoCircomPkFormat(t, "circuit1k")
	testGoCircomPkFormat(t, "circuit5k")
	// testGoCircomPkFormat(t, "circuit10k")
	// testGoCircomPkFormat(t, "circuit20k")
}

func benchmarkParsePk(b *testing.B, circuit string) {
	pkJson, err := ioutil.ReadFile("../testdata/" + circuit + "/proving_key.json")
	require.Nil(b, err)

	pkBinFile, err := os.Open("../testdata/" + circuit + "/proving_key.bin")
	require.Nil(b, err)
	defer pkBinFile.Close()

	pkGoBinFile, err := os.Open("../testdata/" + circuit + "/proving_key.go.bin")
	require.Nil(b, err)
	defer pkGoBinFile.Close()

	b.Run("ParsePkJson "+circuit, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = ParsePk(pkJson)
			require.Nil(b, err)
		}
	})
	b.Run("ParsePkBin "+circuit, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pkBinFile.Seek(0, 0)
			_, err = ParsePkBin(pkBinFile)
			require.Nil(b, err)
		}
	})
	b.Run("ParsePkGoBin "+circuit, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pkGoBinFile.Seek(0, 0)
			_, err = ParsePkGoBin(pkGoBinFile)
			require.Nil(b, err)
		}
	})
}

func BenchmarkParsePk(b *testing.B) {
	benchmarkParsePk(b, "circuit1k")
	benchmarkParsePk(b, "circuit5k")
	// benchmarkParsePk(b, "circuit10k")
	// benchmarkParsePk(b, "circuit20k")
}
