package main

import (
	"bytes"
	"os"

	"github.com/kysee/zkp/zk-asset/types"
)

func main() {
	// 회로 컴파일 (Merkle tree depth = 5)
	const depth = 5
	_, _, vk := types.CompileCircuit(depth)

	// contracts 디렉토리 생성
	err := os.MkdirAll("contracts", 0755)
	if err != nil {
		panic(err)
	}

	// Solidity verifier 생성
	var buf bytes.Buffer
	err = vk.ExportSolidity(&buf)
	if err != nil {
		panic(err)
	}

	// Verifier.sol 파일로 저장
	err = os.WriteFile("contracts/PlonkVerifier.sol", buf.Bytes(), 0644)
	if err != nil {
		panic(err)
	}

	println("✅ Solidity verifier generated: contracts/PlonkVerifier.sol")
}
