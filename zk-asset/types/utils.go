package types

import crand "crypto/rand"

func RandBytes(n int) []byte {
	rbz := make([]byte, n)
	_, _ = crand.Read(rbz)
	return rbz
}
