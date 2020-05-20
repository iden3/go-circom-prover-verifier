package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/iden3/go-circom-prover-verifier/parsers"
	"github.com/iden3/go-circom-prover-verifier/prover"
	"github.com/iden3/go-circom-prover-verifier/verifier"
)

const version = "v0.0.1"

func main() {
	fmt.Println("go-circom-prover-verifier")
	fmt.Println("		", version)

	prove := flag.Bool("prove", false, "prover mode")
	verify := flag.Bool("verify", false, "verifier mode")
	convert := flag.Bool("convert", false, "convert mode, to convert between proving_key.json to proving_key.go.bin")

	provingKeyPath := flag.String("pk", "proving_key.json", "provingKey path")
	witnessPath := flag.String("witness", "witness.json", "witness path")
	proofPath := flag.String("proof", "proof.json", "proof path")
	verificationKeyPath := flag.String("vk", "verification_key.json", "verificationKey path")
	publicPath := flag.String("public", "public.json", "public signals path")
	provingKeyBinPath := flag.String("pkbin", "proving_key.go.bin", "provingKey Bin path")

	flag.Parse()

	if *prove {
		err := cmdProve(*provingKeyPath, *witnessPath, *proofPath, *publicPath)
		if err != nil {
			fmt.Println("Error:", err)
		}
		os.Exit(0)
	} else if *verify {
		err := cmdVerify(*proofPath, *verificationKeyPath, *publicPath)
		if err != nil {
			fmt.Println("Error:", err)
		}
		os.Exit(0)
	} else if *convert {
		err := cmdConvert(*provingKeyPath, *provingKeyBinPath)
		if err != nil {
			fmt.Println("Error:", err)
		}
		os.Exit(0)
	}
	flag.PrintDefaults()
}

func cmdProve(provingKeyPath, witnessPath, proofPath, publicPath string) error {
	fmt.Println("zkSNARK Groth16 prover")

	fmt.Println("Reading proving key file:", provingKeyPath)
	provingKeyJson, err := ioutil.ReadFile(provingKeyPath)
	if err != nil {
		return err
	}
	pk, err := parsers.ParsePk(provingKeyJson)
	if err != nil {
		return err
	}

	fmt.Println("Reading witness file:", witnessPath)
	witnessJson, err := ioutil.ReadFile(witnessPath)
	if err != nil {
		return err
	}
	w, err := parsers.ParseWitness(witnessJson)
	if err != nil {
		return err
	}

	fmt.Println("Generating the proof")
	beforeT := time.Now()
	proof, pubSignals, err := prover.GenerateProof(pk, w)
	if err != nil {
		return err
	}
	fmt.Println("proof generation time elapsed:", time.Since(beforeT))

	proofStr, err := parsers.ProofToJson(proof)
	if err != nil {
		return err
	}

	// write output
	err = ioutil.WriteFile(proofPath, proofStr, 0644)
	if err != nil {
		return err
	}
	publicStr, err := json.Marshal(parsers.ArrayBigIntToString(pubSignals))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(publicPath, publicStr, 0644)
	if err != nil {
		return err
	}
	fmt.Println("Proof stored at:", proofPath)
	fmt.Println("PublicSignals stored at:", publicPath)
	return nil
}

func cmdVerify(proofPath, verificationKeyPath, publicPath string) error {
	fmt.Println("zkSNARK Groth16 verifier")

	proofJson, err := ioutil.ReadFile(proofPath)
	if err != nil {
		return err
	}
	vkJson, err := ioutil.ReadFile(verificationKeyPath)
	if err != nil {
		return err
	}
	publicJson, err := ioutil.ReadFile(publicPath)
	if err != nil {
		return err
	}

	public, err := parsers.ParsePublicSignals(publicJson)
	if err != nil {
		return err
	}
	proof, err := parsers.ParseProof(proofJson)
	if err != nil {
		return err
	}
	vk, err := parsers.ParseVk(vkJson)
	if err != nil {
		return err
	}

	v := verifier.Verify(vk, proof, public)
	fmt.Println("verification:", v)
	return nil
}

func cmdConvert(provingKeyPath, provingKeyBinPath string) error {
	fmt.Println("Convertion tool")

	provingKeyJson, err := ioutil.ReadFile(provingKeyPath)
	if err != nil {
		return err
	}
	pk, err := parsers.ParsePk(provingKeyJson)
	if err != nil {
		return err
	}

	fmt.Printf("Converting proving key json (%s)\nto go proving key binary (%s)\n", provingKeyPath, provingKeyBinPath)
	pkGBin, err := parsers.PkToGoBin(pk)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(provingKeyBinPath, pkGBin, 0644)

	return nil
}
