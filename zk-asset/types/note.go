package types

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/utils"
	"math/big"
)

type Note struct {
	Version byte
	PubKey  signature.PublicKey
	Balance *uint256.Int
	Salt    []byte
}

func NewNote(balance *uint256.Int, salt []byte) *Note {
	prvKey, _ := eddsa.GenerateKey(crand.Reader)
	pubKey := prvKey.Public()
	return &Note{
		PubKey:  pubKey,
		Balance: balance,
		Salt:    salt,
	}
}

func (n *Note) Bytes() []byte {
	_pub := n.PubKey.(*eddsa.PublicKey)
	ax := _pub.A.X.Bytes()
	ay := _pub.A.Y.Bytes()
	bz := []byte{n.Version}
	bz = append(ax[:], ay[:]...)
	bz = append(bz, n.Balance.Bytes()...)
	bz = append(bz, n.Salt...)
	return bz
}

func (n *Note) Commitment() []byte {
	return utils.Poseidon2Hash(n.Bytes())
}

// SecretNote represents the plaintext data of a note that will be encrypted and sent to the recipient.
// It is analogous to the Note Plaintext structure in Zcash Sapling.
type SecretNote struct {
	// Version indicates the format version of the note.
	Version byte

	// Balance is the amount of the asset represented by the note.
	Balance *uint256.Int

	// Salt is the random value (rcm) used to generate the note commitment.
	Salt []byte

	// Memo is an arbitrary message field that can be included in the transaction.
	Memo []byte
}

// Bytes returns the RLP-encoded representation of the SecretNote as a byte slice.
// It panics if the encoding fails.
func (sn *SecretNote) Bytes() []byte {
	b, err := rlp.EncodeToBytes(sn)
	if err != nil {
		// Typically, a Bytes() method does not return an error.
		// We treat this as a critical internal error and panic.
		panic(fmt.Sprintf("failed to RLP encode SecretNote: %v", err))
	}
	return b
}

// EncodeRLP encodes the SecretNote into RLP format.
// This method implements the rlp.Encoder interface.
func (sn *SecretNote) EncodeRLP(w *bytes.Buffer) error {
	// Convert Balance to *big.Int for encoding, as rlp has built-in support for it.
	balanceBig := sn.Balance.ToBig()

	// Encode fields in order into a slice for rlp.Encode.
	return rlp.Encode(w, []interface{}{
		sn.Version,
		balanceBig,
		sn.Salt,
		sn.Memo,
	})
}

// DecodeRLP decodes RLP data into the SecretNote.
// This method implements the rlp.Decoder interface.
func (sn *SecretNote) DecodeRLP(s *rlp.Stream) error {
	// Use a temporary struct for decoding.
	var temp struct {
		Version byte
		Balance *big.Int // Decode into *big.Int first.
		Salt    []byte
		Memo    []byte
	}

	if err := s.Decode(&temp); err != nil {
		return err
	}

	// Convert *big.Int back to *uint256.Int with an overflow check.
	balance, overflow := uint256.FromBig(temp.Balance)
	if overflow {
		return fmt.Errorf("balance value overflows uint256")
	}

	sn.Version = temp.Version
	sn.Balance = balance
	sn.Salt = temp.Salt
	sn.Memo = temp.Memo

	return nil
}
