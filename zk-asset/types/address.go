package types

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	jubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

const ver = 0x01

func EncodeAddress(payload []byte) string {
	return "bz" + base58.CheckEncode(payload, ver)
}

func DecodeAddress(addr string) ([]byte, error) {
	if !strings.HasPrefix(addr, "bz") {
		return nil, fmt.Errorf("wrong prefix: got(%s)", addr[:2])
	}
	bz, _ver, err := base58.CheckDecode(addr[2:])
	if err != nil {
		return nil, err
	}
	if _ver != ver {
		return nil, fmt.Errorf("wrong version: expected(%d), got(%d)", ver, _ver)
	}
	return bz, nil
}

func Pub2Addr(pubKey *jubjub.PublicKey) string {
	return EncodeAddress(pubKey.Bytes())
}

func Addr2Pub(addr string) *jubjub.PublicKey {
	pubKeyBytes, err := DecodeAddress(addr)
	if err != nil {
		panic(err)
	}
	pubKey := new(jubjub.PublicKey)
	_, _ = pubKey.A.SetBytes(pubKeyBytes)
	return pubKey
}
