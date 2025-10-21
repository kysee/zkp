package prover

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/zk-asset/crypto"
	"github.com/kysee/zkp/zk-asset/types"
	"github.com/kysee/zkp/zk-asset/verifier"
)

type Wallet struct {
	Address     string
	PrivateKey  signature.Signer
	sharedNotes []*types.SharedNote
}

var (
	Wallets = make([]*Wallet, 0)
)

func init() {
	for i := 0; i < 10; i++ {
		w := NewWallet()
		Wallets = append(Wallets, w)

		verifier.InitMint(w.Address, uint256.NewInt(100))
	}

	for _, w := range Wallets {
		_ = w.SyncSharedNotes()
		b := w.GetBalance()
		fmt.Printf("prover=%s, balance=%s\n", w.Address, b.Dec())
	}
}

func NewWallet() *Wallet {
	prvk, _ := crypto.NewKey()
	return &Wallet{
		Address:    types.Pub2Addr(prvk.Public()),
		PrivateKey: prvk,
	}
}

func (w *Wallet) AddSharedNote(note *types.SharedNote) {
	w.sharedNotes = append(w.sharedNotes, note)
}

func (w *Wallet) GetSharedNote(idx int) *types.SharedNote {
	if idx < len(w.sharedNotes) {
		return w.sharedNotes[idx]
	}
	return nil
}

func (w *Wallet) GetSharedNotesCount() int {
	return len(w.sharedNotes)
}

func (w *Wallet) SyncSharedNotes() int {
	w.ClearSharedNotes()

	// find my shared notes
	for i := 0; ; i++ {
		tx := verifier.GetZKTx(i)
		if tx == nil {
			break
		}

		for i, sn := range tx.NewSecretNotes {
			if len(sn) == 0 {
				continue
			}
			_sharedNote, err := types.DecryptSharedNote(sn, nil, w.PrivateKey)
			if err != nil {
				continue
			}
			_note := _sharedNote.ToNoteOf(w.PrivateKey.Public())

			// 1. _ncmt == tx.NewNoteCommitments[i]
			_ncmt := _note.Commitment()
			if !bytes.Equal(_ncmt, tx.NewNoteCommitments[i]) {
				fmt.Printf("wrong secret note: not same as tx note commitment. expected(%x), got(%x)\n", tx.NewNoteCommitments[i], _ncmt)
				continue
			}

			// 2. check the note is used or not (the nullifier exists or not)
			nullifier := _note.Nullifier(w.getPrvScalar())
			if verifier.FindNoteNullifier(nullifier) != nil {
				// already spent
				fmt.Printf("note already spent: %x\n", nullifier)
				continue
			}

			// success
			w.AddSharedNote(_sharedNote)
		}

	}
	return w.GetSharedNotesCount()
}

func (w *Wallet) ClearSharedNotes() {
	w.sharedNotes = make([]*types.SharedNote, 0)
}

func (w *Wallet) GetBalance() *uint256.Int {
	ret := uint256.NewInt(0)
	for _, n := range w.sharedNotes {
		ret = ret.Add(ret, n.Balance)
	}
	return ret
}

func (w *Wallet) getPrvScalar() ([]byte, []byte) {
	s := w.PrivateKey.Bytes()[32:64]
	return s[:16], s[16:32]
}
