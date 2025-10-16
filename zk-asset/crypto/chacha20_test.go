package crypto

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Encrypt(t *testing.T) {
	m := []byte("hello")

	sharedSecret := make([]byte, 32)
	n, err := crand.Read(sharedSecret)
	require.NoError(t, err)
	require.Equal(t, 32, n)

	saplingKDF, err := SaplingKDF(sharedSecret, 44)
	require.NoError(t, err)
	require.Equal(t, 44, len(saplingKDF))

	encKey := saplingKDF[:32]
	nonce := saplingKDF[32:44]

	enc, err := ChaCha20Poly1305_Encrypt(encKey, nonce, m, []byte("adata"))
	require.NoError(t, err)

	dec, err := ChaCha20Poly1305_Decrypt(encKey, nonce, enc, []byte("adata"))
	require.NoError(t, err)

	require.Equal(t, m, dec)
}
