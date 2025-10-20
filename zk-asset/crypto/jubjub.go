package crypto

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/big"

	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	jubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	"golang.org/x/crypto/blake2s"
)

//
// GenerateKey

func NewKey() (signature.Signer, error) {
	return jubjub.GenerateKey(crand.Reader)
}

func NewPub() signature.PublicKey {
	return new(jubjub.PublicKey)
}

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

// SaplingKDF derives a key stream of a specified length from a shared secret using BLAKE2s.
// This function follows the PRF^expand logic, similar to HKDF-Expand (RFC 5869),
// as defined in the Zcash Sapling specification.
func SaplingKDF(sharedSecret []byte, outputLen int) ([]byte, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("sharedSecret must be 32 bytes")
	}

	// Use the personalization string defined in the Zcash Sapling spec for PRF^expand.
	personalization := []byte("Zcash_ExpandSeed")

	var keyStream []byte
	var counter byte = 1 // The counter must start at 1.
	for len(keyStream) < outputLen {
		// Create a new hash instance for each iteration to avoid state pollution.
		h, err := blake2s.New256(personalization)
		if err != nil {
			return nil, fmt.Errorf("failed to create blake2s hash: %w", err)
		}
		h.Write(sharedSecret)
		h.Write([]byte{counter})

		// Append the hash result to the key stream.
		keyStream = append(keyStream, h.Sum(nil)...)

		counter++
		// Check for counter overflow, which should not happen in practice for typical output lengths.
		if counter == 0 {
			return nil, errors.New("KDF counter overflow")
		}
	}

	// Truncate the key stream to the desired length.
	return keyStream[:outputLen], nil
}
