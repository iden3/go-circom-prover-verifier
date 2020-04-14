#!/bin/sh

echo "testdata/small/circuit.circom"
cd testdata/small
echo "compiling circuit"
circom circuit.circom -r1cs --wasm --sym
echo "generating setup"
snarkjs setup
sed -i 's/null/["0","0","0"]/g' proving_key.json
echo "calculating witness"
snarkjs calculatewitness --wasm circuit.wasm --input input.json --witness witness.json

echo "\ntestdata/big/circuit.circom"
cd ../big
echo "compiling circuit"
circom circuit.circom -r1cs --wasm --sym
echo "generating setup"
snarkjs setup
sed -i 's/null/["0","0","0"]/g' proving_key.json
echo "calculating witness"
snarkjs calculatewitness --wasm circuit.wasm --input input.json --witness witness.json
