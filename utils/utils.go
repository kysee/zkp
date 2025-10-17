package utils

import (
	"hash"

	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	gnark_hash "github.com/consensys/gnark-crypto/hash"
)

var (
	CURVEID = twistededwards.BN254
)

func DefaultHasher() hash.Hash {
	return MiMCHasher()
}

func MiMCHasher() hash.Hash {
	return gnark_hash.MIMC_BN254.New()
}

func Poseidon2Hasher() hash.Hash {
	return gnark_hash.POSEIDON2_BN254.New()
}

func MiMCHash(ins ...[]byte) []byte {
	hasher := MiMCHasher()
	hasher.Reset()
	for _, in := range ins {
		if len(in) > bn254mimc.BlockSize {
			hasher.Write(in)
			zeroCnt := len(in) % bn254mimc.BlockSize
			if zeroCnt > 0 {
				zeroCnt = bn254mimc.BlockSize - zeroCnt
				zeroBz := make([]byte, zeroCnt)
				hasher.Write(zeroBz)
			}
		} else {
			inblock := make([]byte, bn254mimc.BlockSize)
			copy(inblock[bn254mimc.BlockSize-len(in):], in)
			hasher.Write(inblock)
		}
	}

	return hasher.Sum(nil)
}

func Poseidon2Hash(ins ...[]byte) []byte {
	hasher := Poseidon2Hasher()
	hasher.Reset()
	for _, in := range ins {
		hasher.Write(in)
	}
	return hasher.Sum(nil)
}
