package types

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/utils"
)

type NoteCommitment []byte
type NoteNullifier []byte

type Note struct {
	Version byte
	// todo: Apply diversifier of zcash
	PubKey  signature.PublicKey
	Balance *uint256.Int
	Salt    []byte
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
	_pub := n.PubKey.(*eddsa.PublicKey)
	ax := _pub.A.X.Bytes()
	ay := _pub.A.Y.Bytes()

	//// Salt는 랜덤 32바이트인데 field modulus를 초과할 수 있으므로
	//// field element로 변환 후 다시 bytes로 변환하여 일관성 보장
	//var saltElem fr.Element
	//saltElem.SetBytes(n.Salt)
	//saltBytes := saltElem.Bytes()

	h := utils.DefaultHashSum(
		[]byte{n.Version},
		ax[:],
		ay[:],
		n.Balance.Bytes(),
		n.Salt) //saltBytes[:])
	return h
}

func (n *Note) Nullifier(sk0, sk1 []byte) []byte {
	// Step 1: Nullifier key generation
	nk := utils.DefaultHashSum(sk0, sk1)

	// Step 2: Nullifier 계산
	// nf = Hash(nk, note_commitment)
	return utils.DefaultHashSum(
		nk,
		n.Commitment(),
	)
}

func (n *Note) ToSecretNote() *SecretNote {
	return &SecretNote{
		Version: n.Version,
		Balance: n.Balance,
		Salt:    n.Salt,
		Memo:    []byte{},
	}
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

func (sn *SecretNote) ToNoteOf(pubKey signature.PublicKey) *Note {
	return &Note{
		Version: sn.Version,
		PubKey:  pubKey,
		Balance: sn.Balance,
		Salt:    sn.Salt,
	}
}
