package utils

import (
	"hash"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	gnark_hash "github.com/consensys/gnark-crypto/hash"
)

var (
	CURVEID = twistededwards.BN254
)

func DefaultHasher() hash.Hash {
	//return &poseidon2Wrapper{
	//	inner: gnark_hash.POSEIDON2_BN254.New(),
	//}
	return MiMCHasher()
}

func DefaultHashSum(ins ...[]byte) []byte {
	return MiMCHash(ins...)
}

func MiMCHasher() hash.Hash {
	return gnark_hash.MIMC_BN254.New()
}

func MiMCHash(ins ...[]byte) []byte {
	hasher := MiMCHasher()

	blockSize := hasher.Size()

	hasher.Reset()
	for _, in := range ins {

		for i := 0; i < len(in); i += blockSize {
			end := i + blockSize
			if end > len(in) {
				end = len(in)
			}
			chunk := in[i:end]

			if len(chunk) == blockSize {
				// this value may be greater than the modulus; convert to fr.Element
				var elem fr.Element
				elem.SetBytes(chunk)
				// canonical form
				chunk = elem.Marshal()
			}
			if _, err := hasher.Write(chunk); err != nil {
				panic(err)
			}
		}
	}
	return hasher.Sum(nil)
}

// poseidon2Wrapper wraps Poseidon2 hasher to handle inputs that may exceed Fr modulus
type poseidon2Wrapper struct {
	inner hash.Hash
}

func (w *poseidon2Wrapper) Write(p []byte) (n int, err error) {
	// Poseidon2는 SetBytesCanonical을 사용하므로,
	// 입력 바이트가 BN254 Fr modulus보다 작아야 합니다.
	const blockSize = fr.Bytes // 32 bytes

	originalLen := len(p)
	for i := 0; i < len(p); i += blockSize {
		end := i + blockSize
		if end > len(p) {
			end = len(p)
		}
		chunk := p[i:end]

		// Fr Element로 변환 (SetBytes는 자동으로 modulo 연산 수행)
		var elem fr.Element
		elem.SetBytes(chunk)

		// canonical 형태로 marshal하여 inner hasher에 입력
		if _, err := w.inner.Write(elem.Marshal()); err != nil {
			return 0, err
		}
	}
	return originalLen, nil
}

func (w *poseidon2Wrapper) Sum(b []byte) []byte {
	return w.inner.Sum(b)
}

func (w *poseidon2Wrapper) Reset() {
	w.inner.Reset()
}

func (w *poseidon2Wrapper) Size() int {
	return w.inner.Size()
}

func (w *poseidon2Wrapper) BlockSize() int {
	return w.inner.BlockSize()
}
