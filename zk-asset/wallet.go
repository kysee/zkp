package zk_asset

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	jubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	ecc_tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/zk-asset/node"
	"github.com/kysee/zkp/zk-asset/types"
	"github.com/rs/zerolog"
)

type Wallet struct {
	Address     string
	PrivateKey  *jubjub.PrivateKey
	secretNotes []*types.SecretNote
}

func NewWallet() *Wallet {
	prvk, _ := jubjub.GenerateKey(crand.Reader)
	return &Wallet{
		Address:    types.Pub2Addr(&prvk.PublicKey),
		PrivateKey: prvk,
	}
}

func (w *Wallet) AddSecretNote(note *types.SecretNote) {
	w.secretNotes = append(w.secretNotes, note)
}

func (w *Wallet) GetSecretNote(idx int) *types.SecretNote {
	if idx < len(w.secretNotes) {
		return w.secretNotes[idx]
	}
	return nil
}

func (w *Wallet) GetSecretNotesCount() int {
	return len(w.secretNotes)
}

func (w *Wallet) DelSecretNote(note *types.SecretNote) {
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
func (w *Wallet) TransferProof(toAddr string, amt, fee *uint256.Int, provingKey plonk.ProvingKey, ccs constraint.ConstraintSystem) (*types.ZKTx, error) {

	toPubKey := types.Addr2Pub(toAddr)
	salt1 := make([]byte, 32)
	crand.Read(salt1)

	useSecretNote := w.secretNotes[0]
	usedNote := &types.Note{
		Version: 1,
		PubKey:  w.PrivateKey.Public(),
		Balance: useSecretNote.Balance,
		Salt:    useSecretNote.Salt,
	}
	newNote := &types.Note{
		Version: 1,
		PubKey:  toPubKey,
		Balance: amt,
		Salt:    salt1,
	}
	changeNote := &types.Note{
		Version: 1,
		PubKey:  usedNote.PubKey,
		Balance: new(uint256.Int).Sub(useSecretNote.Balance, new(uint256.Int).Add(amt, fee)),
		Salt:    usedNote.Salt,
	}

	//
	// get merkle path info from remote node
	noteCommitment := usedNote.Commitment()

	//fmt.Printf("noteCommitment=%s\n", new(uint256.Int).SetBytes(noteCommitment).Dec())

	rootHash, proofPath, idx, depth, _, err := node.GetNoteCommitmentMerkle(noteCommitment)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("Merkle Info: numLeaves=%d, idx=%d, depth=%d, proofPath.len=%d\n", numLeaves, idx, depth, len(proofPath))

	// verify the proof in plain go using the original short proof
	if !node.VerifyNoteCommitmentProof(noteCommitment, rootHash, idx) {
		return nil, errors.New("the merkle proof in plain go should pass")
	}

	prv0, prv1 := w.getPrvScalar()

	// these are the return values
	nullifier := usedNote.Nullifier(prv0, prv1)
	newNoteC := newNote.Commitment()
	changeNoteC := changeNote.Commitment()

	var assignment types.ZKCircuit
	assignment.SetCurveId(ecc_tedwards.BN254)
	assignment.FromPrv0, assignment.FromPrv1 = prv0, prv1
	assignment.NoteVer = usedNote.Version
	assignment.FromPub.Assign(assignment.GetCurveId(), usedNote.PubKey.Bytes())
	assignment.Balance = usedNote.Balance.Bytes()
	assignment.Salt0 = usedNote.Salt
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
		return nil, err
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
		return nil, err
	}

	bufProof := bytes.NewBuffer(nil)
	if _, err := proof.WriteTo(bufProof); err != nil {
		return nil, err
	}

	return &types.ZKTx{
		ProofBytes:           bufProof.Bytes(),
		MerkleRoot:           rootHash,
		Nullifier:            nullifier,
		NewNoteCommitment:    newNoteC,
		ChangeNoteCommitment: changeNoteC,
	}, nil
}

var gnarkLogger = zerolog.New(os.Stdout).Level(zerolog.TraceLevel).With().Timestamp().Logger()
