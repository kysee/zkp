package types

import (
	crand "crypto/rand"
	"fmt"
	"strings"
	"testing"

	jubjub "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"github.com/stretchr/testify/require"
)

func TestAddressCodec(t *testing.T) {
	pubKeyBytes := make([]byte, 32)
	_, _ = crand.Read(pubKeyBytes)

	addr0 := EncodeAddress(pubKeyBytes)
	require.True(t, strings.HasPrefix(addr0, "bz"))
	fmt.Println("address", addr0)

	// wrong prefix
	_addr0 := fmt.Sprintf("cz%s", addr0[2:])
	_, err := DecodeAddress(_addr0)
	require.ErrorContains(t, err, "wrong prefix")

	bzAddr, err := DecodeAddress(addr0)
	require.NoError(t, err)
	require.Equal(t, pubKeyBytes, bzAddr)
}

func TestAddressPubKey(t *testing.T) {
	prv, err := jubjub.GenerateKey(crand.Reader)
	require.NoError(t, err)
	pubKey0 := &prv.PublicKey
	addr := Pub2Addr(pubKey0)
	fmt.Println("address", addr)

	pubKey1 := Addr2Pub(addr)
	require.Equal(t, pubKey0, pubKey1)
}
