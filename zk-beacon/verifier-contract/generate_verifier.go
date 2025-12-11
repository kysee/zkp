package main

import (
	"bytes"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/kysee/zkp/zk-beacon/circuit"
)

func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.ScUpdateVerifierCircuit{})
	if err != nil {
		panic(err)
	}

	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	if err := os.MkdirAll("contracts", 0755); err != nil {
		panic(err)
	}
	// Solidity verifier 생성
	var buf bytes.Buffer
	err = vk.ExportSolidity(&buf)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("contracts/SCUpdator.sol", buf.Bytes(), 0644)
	if err != nil {
		panic(err)
	}

	println("✅ Solidity verifier generated: contracts/SCUpdator.sol")
}
