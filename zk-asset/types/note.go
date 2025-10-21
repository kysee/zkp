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
	"github.com/kysee/zkp/zk-asset/crypto"
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

func (n *Note) ToSharedNote() *SharedNote {
	return &SharedNote{
		Version: n.Version,
		Balance: n.Balance,
		Salt:    n.Salt,
		Memo:    []byte{},
	}
}

// SharedNote represents the plaintext data of a note that will be encrypted and sent to the recipient.
// It is analogous to the Note Plaintext structure in Zcash Sapling.
type SharedNote struct {
	// Version indicates the format version of the note.
	Version byte

	// Balance is the amount of the asset represented by the note.
	Balance *uint256.Int

	// Salt is the random value (rcm) used to generate the note commitment.
	Salt []byte

	// Memo is an arbitrary message field that can be included in the transaction.
	Memo []byte
}

// Bytes returns the RLP-encoded representation of the SharedNote as a byte slice.
// It panics if the encoding fails.
func (sn *SharedNote) Bytes() []byte {
	b, err := rlp.EncodeToBytes(sn)
	if err != nil {
		// Typically, a Bytes() method does not return an error.
		// We treat this as a critical internal error and panic.
		panic(fmt.Sprintf("failed to RLP encode SharedNote: %v", err))
	}
	return b
}

// EncodeRLP encodes the SharedNote into RLP format.
// This method implements the rlp.Encoder interface.
func (sn *SharedNote) EncodeRLP(w *bytes.Buffer) error {
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

// DecodeRLP decodes RLP data into the SharedNote.
// This method implements the rlp.Decoder interface.
func (sn *SharedNote) DecodeRLP(s *rlp.Stream) error {
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

func (sn *SharedNote) ToNoteOf(pubKey signature.PublicKey) *Note {
	return &Note{
		Version: sn.Version,
		PubKey:  pubKey,
		Balance: sn.Balance,
		Salt:    sn.Salt,
	}
}

func (sn *SharedNote) Encrypt(sharedKey, ad []byte) ([]byte, error) {
	saplingKDF, err := crypto.SaplingKDF(sharedKey, 44)
	if err != nil {
		return nil, err
	}
	encKey := saplingKDF[:32]
	nonce := saplingKDF[32:44]

	return crypto.ChaCha20Poly1305_Encrypt(encKey, nonce, sn.Bytes(), ad)
}

func (sn *SharedNote) Decrypt(sharedKey, ciphertext, ad []byte) error {
	saplingKDF, err := crypto.SaplingKDF(sharedKey, 44)
	if err != nil {
		return err
	}
	encKey := saplingKDF[:32]
	nonce := saplingKDF[32:44]

	plaintext, err := crypto.ChaCha20Poly1305_Decrypt(encKey, nonce, ciphertext, ad)
	return rlp.DecodeBytes(plaintext, sn)
}

// EncryptSharedNote encrypts a SharedNote and returns the ciphertext and temporarily public key
func EncryptSharedNote(sn *SharedNote, ad []byte, receiverPubKey signature.PublicKey) ([]byte, error) {
	// Encrypt the SharedNote
	tmpKey, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	sharedSecret, err := crypto.ECDHSharedSecret(tmpKey, receiverPubKey)
	if err != nil {
		return nil, err
	}

	ciphertext, err := sn.Encrypt(sharedSecret, ad)
	if err != nil {
		return nil, err
	}
	return append(tmpKey.Public().Bytes(), ciphertext...), nil
}

func DecryptSharedNote(secretNote []byte, ad []byte, myPrivKey signature.Signer) (*SharedNote, error) {
	bzSenderPubKey, ciphertext := secretNote[:32], secretNote[32:]
	tmpPubKey := crypto.NewPub()
	tmpPubKey.SetBytes(bzSenderPubKey)
	sharedSecret, err := crypto.ECDHSharedSecret(myPrivKey, tmpPubKey)

	sn := &SharedNote{}
	err = sn.Decrypt(sharedSecret, ciphertext, ad)
	return sn, err
}
