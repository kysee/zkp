package crypto

import (
	"errors"
	"fmt"
	"math/big"

	tedwards "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	jubjub "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"golang.org/x/crypto/blake2s"
)

// ECDHEComputeSharedSecret computes the ECDHE shared secret
// sharedSecret = privateKey * otherPublicKey
func ECDHEComputeSharedSecret(privateKey *jubjub.PrivateKey, otherPublicKey *jubjub.PublicKey) ([]byte, error) {
	// Verify the other public key is on the curve
	if !otherPublicKey.A.IsOnCurve() {
		return nil, errors.New("other public key is not on curve")
	}

	// Compute shared secret: privateKey * otherPublicKey
	var sharedSecret tedwards.PointAffine

	//scalarBigInt := privateKey.scalar.BigInt(nil)
	scalarBytes := privateKey.Bytes()
	scalarBigInt := new(big.Int).SetBytes(scalarBytes[32:64])
	sharedSecret.ScalarMultiplication(&otherPublicKey.A, scalarBigInt)

	if !sharedSecret.IsOnCurve() {
		return nil, errors.New("computed shared secret is not on curve")
	}

	hasher, err := blake2s.New256(nil)
	if err != nil {
		return nil, err
	}
	ax := sharedSecret.X.Bytes()
	hasher.Write(ax[:])
	return hasher.Sum(nil), nil
}

// saplingKDF는 BLAKE2s를 사용하여 공유 비밀키로부터 키 스트림을 유도합니다.
// PRF^expand 로직을 따릅니다.
func SaplingKDF(sharedSecret []byte, outputLen int) ([]byte, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("sharedSecret must be 32 bytes")
	}

	// BLAKE2s 해셔를 KDF 목적으로 생성
	h, err := blake2s.New256([]byte("beatoz_sapling_KDF"))
	if err != nil {
		return nil, fmt.Errorf("failed to create blake2s hash: %w", err)
	}

	h.Write(sharedSecret)

	// 카운터를 1씩 증가시키며 필요한 길이의 출력을 생성
	var keyStream []byte
	var counter byte = 0
	for len(keyStream) < outputLen {
		// 현재 해시 상태를 복제하여 원본을 유지
		hClone := h

		// 카운터 추가
		hClone.Write([]byte{counter})

		// 해시 결과 추가
		keyStream = append(keyStream, hClone.Sum(nil)...)
		counter++
	}

	// 필요한 길이만큼 잘라서 반환
	return keyStream[:outputLen], nil
}
