package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305_Encrypt encrypts the note plaintext using ChaCha20-Poly1305.
// key: 32-byte key
// nonce: 12-byte nonce
// plaintext: note data to encrypt
// additionalData: data to be authenticated but not encrypted
func ChaCha20Poly1305_Encrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
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

// ChaCha20Poly1305_Decrypt decrypts the note ciphertext using ChaCha20-Poly1305.
// key: 32-byte key
// nonce: 12-byte nonce
// ciphertext: encrypted note data
// additionalData: data to be authenticated but not encrypted
func ChaCha20Poly1305_Decrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("failed to decrypt note: %w", err)
	}
	return plaintext, nil
}
