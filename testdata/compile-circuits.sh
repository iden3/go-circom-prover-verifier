#!/bin/sh

npm install

compile_and_ts_and_witness() {
  echo $(date +"%T") "circom circuit.circom --r1cs --wasm --sym"
  itime="$(date -u +%s)"
  ../node_modules/.bin/circom circuit.circom --r1cs --wasm --sym
  ftime="$(date -u +%s)"
  echo "	($(($(date -u +%s)-$itime))s)"

  echo $(date +"%T") "snarkjs info -r circuit.r1cs"
  ../node_modules/.bin/snarkjs info -r circuit.r1cs

  echo $(date +"%T") "snarkjs setup"
  itime="$(date -u +%s)"
  ../node_modules/.bin/snarkjs setup
  echo "	($(($(date -u +%s)-$itime))s)"
  echo $(date +"%T") "trusted setup generated"

  sed -i 's/null/["0","0","0"]/g' proving_key.json

  echo "calculating witness"
  ../node_modules/.bin/snarkjs calculatewitness --wasm circuit.wasm --input inputs.json --witness witness.json

  echo $(date +"%T") "snarkjs generateverifier"
  itime="$(date -u +%s)"
  ../node_modules/.bin/snarkjs generateverifier
  echo "	($(($(date -u +%s)-$itime))s)"
  echo $(date +"%T") "generateverifier generated"
}

echo "compile & trustesetup for circuit1k"
cd circuit1k
compile_and_ts_and_witness
echo "compile & trustesetup for circuit5k"
cd ../circuit5k
compile_and_ts_and_witness
# echo "compile & trustesetup for circuit10k"
# cd ../circuit10k
# compile_and_ts_and_witness
# echo "compile & trustesetup for circuit20k"
# cd ../circuit20k
# compile_and_ts_and_witness

cd ../

echo "convert witness & pk of circuit1k to bin"
node node_modules/wasmsnark/tools/buildwitness.js -i circuit1k/witness.json -o circuit1k/witness.bin
node node_modules/wasmsnark/tools/buildpkey.js -i circuit1k/proving_key.json -o circuit1k/proving_key.bin

echo "convert witness & pk of circuit5k to bin"
node node_modules/wasmsnark/tools/buildwitness.js -i circuit5k/witness.json -o circuit5k/witness.bin
node node_modules/wasmsnark/tools/buildpkey.js -i circuit5k/proving_key.json -o circuit5k/proving_key.bin

# echo "convert witness & pk of circuit10k to bin"
# node node_modules/wasmsnark/tools/buildwitness.js -i circuit10k/witness.json -o circuit10k/witness.bin
# node node_modules/wasmsnark/tools/buildpkey.js -i circuit10k/proving_key.json -o circuit10k/proving_key.bin
# 
# echo "convert witness & pk of circuit20k to bin"
# node node_modules/wasmsnark/tools/buildwitness.js -i circuit20k/witness.json -o circuit20k/witness.bin
# node node_modules/wasmsnark/tools/buildpkey.js -i circuit20k/proving_key.json -o circuit20k/proving_key.bin

