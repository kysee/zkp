package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptNote encrypts the note plaintext using the ChaCha20-Poly1305 AEAD (Authenticated
// Encryption with Associated Data) scheme.
//
// Parameters:
//   - key: A 32-byte symmetric encryption key.
//   - nonce: A 12-byte nonce, which must be unique for each encryption with the same key.
//   - plaintext: The data to be encrypted (e.g., the serialized SecretNote).
//   - additionalData: Data to be authenticated but not encrypted. In Zcash, this is
//     typically the ephemeral public key (epk).
//
// Returns the ciphertext, which includes the authentication tag.
func EncryptNote(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: must be %d bytes", chacha20poly1305.KeySize)
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid nonce size: must be %d bytes", chacha20poly1305.NonceSize)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 AEAD: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// DecryptNote decrypts the note ciphertext using ChaCha20-Poly1305.
//
// Parameters:
//   - key: The 32-byte symmetric encryption key used for encryption.
//   - nonce: The 12-byte nonce used for encryption.
//   - ciphertext: The encrypted data, including the authentication tag.
//   - additionalData: The associated data that was authenticated. This must match the
//     data used during encryption.
//
// Returns the original plaintext if decryption and authentication are successful.
func DecryptNote(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: must be %d bytes", chacha20poly1305.KeySize)
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid nonce size: must be %d bytes", chacha20poly1305.NonceSize)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		// This error is critical as it indicates either a wrong key/nonce or
		// that the ciphertext or additionalData has been tampered with.
		return nil, fmt.Errorf("failed to decrypt note: %w", err)
	}
	return plaintext, nil
}
