#!/bin/sh

# rm */*.json
find */*.json -type f -not -name 'inputs.json' -delete
rm */*.wasm
rm */*.cpp
rm */*.sym
rm */*.r1cs
rm */*.sol
rm */*.bin
