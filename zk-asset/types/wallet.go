package types

import (
	"bytes"
	crand "crypto/rand"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	ecc_tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/zk-asset/crypto"
	"github.com/rs/zerolog"
)

type Wallet struct {
	Address     string
	PrivateKey  signature.Signer
	secretNotes []*SecretNote
}

var (
	Wallets = make([]*Wallet, 0)
)

func NewWallet() *Wallet {
	prvk, _ := crypto.NewKey()
	return &Wallet{
		Address:    Pub2Addr(prvk.Public()),
		PrivateKey: prvk,
	}
}

func (w *Wallet) AddSecretNote(note *SecretNote) {
	w.secretNotes = append(w.secretNotes, note)
}

func (w *Wallet) GetSecretNote(idx int) *SecretNote {
	if idx < len(w.secretNotes) {
		return w.secretNotes[idx]
	}
	return nil
}

func (w *Wallet) GetSecretNotesCount() int {
	return len(w.secretNotes)
}

func (w *Wallet) DelSecretNote(note *SecretNote) {
	found := -1
	for i, n := range w.secretNotes {
		if bytes.Equal(n.Salt, note.Salt) {
			found = i
			break
		}
	}
	if found >= 0 {
		w.secretNotes = append(w.secretNotes[:found], w.secretNotes[found+1:]...)
	}
}

func (w *Wallet) GetBalance() *uint256.Int {
	ret := uint256.NewInt(0)
	for _, n := range w.secretNotes {
		ret = ret.Add(ret, n.Balance)
	}
	return ret
}

func (w *Wallet) getPrvScalar() ([]byte, []byte) {
	s := w.PrivateKey.Bytes()[32:64]
	return s[:16], s[16:32]
}

// TransferProof generates proof and returns `*ZKTx`
func (w *Wallet) TransferProof(
	toAddr string, amt, fee *uint256.Int,
	usingNote *Note,
	rootHash []byte, proofPath [][]byte, depth int, idx uint64,
	provingKey plonk.ProvingKey, ccs constraint.ConstraintSystem,
) (*ZKTx, []*Note, error) {

	toPubKey := Addr2Pub(toAddr)
	salt1 := make([]byte, 32)
	crand.Read(salt1)

	newNote := &Note{
		Version: 1,
		PubKey:  toPubKey,
		Balance: amt,
		Salt:    salt1,
	}
	newSecretNote := newNote.ToSecretNote()
	encNewSecretNote, senderTmPubKey, err := EncryptSecretNote(newSecretNote, nil, toPubKey)

	changeNote := &Note{
		Version: 1,
		PubKey:  usingNote.PubKey,
		Balance: new(uint256.Int).Sub(usingNote.Balance, new(uint256.Int).Add(amt, fee)),
		Salt:    usingNote.Salt,
	}

	//
	// get merkle path info from remote node
	noteCommitment := usingNote.Commitment()

	//fmt.Printf("noteCommitment=%s\n", new(uint256.Int).SetBytes(noteCommitment).Dec())

	prv0, prv1 := w.getPrvScalar()

	// these are the return values
	nullifier := usingNote.Nullifier(prv0, prv1)
	newNoteC := newNote.Commitment()
	changeNoteC := changeNote.Commitment()

	var assignment ZKCircuit
	assignment.SetCurveId(ecc_tedwards.BN254)
	assignment.FromPrv0, assignment.FromPrv1 = prv0, prv1
	assignment.NoteVer = usingNote.Version
	assignment.FromPub.Assign(assignment.GetCurveId(), usingNote.PubKey.Bytes())
	assignment.Balance = usingNote.Balance.Bytes()
	assignment.Salt0 = usingNote.Salt
	assignment.NoteCommitment = noteCommitment
	assignment.NoteIdx = idx
	assignment.NoteMerkleRoot = rootHash

	// Proof path 할당
	// GetNoteCommitmentMerkle이 이미 full depth로 패딩된 proof를 반환
	assignment.NoteMerklePath = make([]frontend.Variable, depth+1)
	for i := 0; i < len(assignment.NoteMerklePath); i++ {
		var v []byte
		if i < len(proofPath) {
			v = proofPath[i]
		} else {
			v = []byte{0x0}
		}
		assignment.NoteMerklePath[i] = v
	}
	assignment.Amount = amt.Bytes()
	assignment.Fee = fee.Bytes()
	assignment.ToPub.Assign(assignment.GetCurveId(), toPubKey.Bytes())
	assignment.Salt1 = salt1
	assignment.NewNoteCommitment = newNoteC
	assignment.ChangeNoteCommitment = changeNoteC
	assignment.Nullifier = nullifier

	wtn, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	proof, err := plonk.Prove(
		ccs,
		provingKey,
		wtn,
		backend.WithSolverOptions(
			solver.WithLogger(gnarkLogger),
		),
	)

	if err != nil {
		return nil, nil, err
	}

	bufProof := bytes.NewBuffer(nil)
	if _, err := proof.WriteTo(bufProof); err != nil {
		return nil, nil, err
	}

	return &ZKTx{
		ProofBytes:           bufProof.Bytes(),
		MerkleRoot:           rootHash,
		Nullifier:            nullifier,
		ChangeNoteCommitment: changeNoteC,
		NewNoteCommitment:    newNoteC,
		EncryptedSecretNote:  append(senderTmPubKey, encNewSecretNote...),
	}, []*Note{newNote, changeNote}, nil
}

var gnarkLogger = zerolog.New(os.Stdout).Level(zerolog.TraceLevel).With().Timestamp().Logger()
