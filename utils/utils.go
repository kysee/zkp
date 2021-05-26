package utils

import (
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
)

var (
	HASHER = hash.MIMC_BN254.New("seed")
)

func ComputeHash(ins ...[]byte) []byte {
	HASHER.Reset()
	for _, in := range ins {
		if len(in) > bn254mimc.BlockSize {
			HASHER.Write(in)
			zeroCnt := len(in) % bn254mimc.BlockSize
			if zeroCnt > 0 {
				zeroCnt = bn254mimc.BlockSize - zeroCnt
				zeroBz := make([]byte, zeroCnt)
				HASHER.Write(zeroBz)
			}
		} else {
			inblock := make([]byte, bn254mimc.BlockSize)
			copy(inblock[bn254mimc.BlockSize-len(in):], in)
			HASHER.Write(inblock)
		}

	}
	return HASHER.Sum(nil)
}
