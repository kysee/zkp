package zk_asset

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	jubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	ecc_tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-asset/common"
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

func (w *Wallet) TransferProof(toAddr string, amt, fee *uint256.Int, ccs constraint.ConstraintSystem) plonk.Proof {
	toPubKey := types.Addr2Pub(toAddr)
	salt1 := make([]byte, 32)
	crand.Read(salt1)

	useSecretNote := w.secretNotes[0]
	noteSpent := &types.Note{
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
		PubKey:  noteSpent.PubKey,
		Balance: new(uint256.Int).Sub(useSecretNote.Balance, new(uint256.Int).Add(amt, fee)),
		Salt:    noteSpent.Salt,
	}

	//
	// get merkle path info from remote node
	noteCommitment := noteSpent.Commitment()
	fmt.Printf("noteCommitment=%s\n", new(uint256.Int).SetBytes(noteCommitment).Dec())

	rootHash, proofPath, idx, depth, numLeaves, err := common.GetNoteCommitmentMerkle(noteCommitment)
	if err != nil {
		panic(err)
	}
	// verify the proof in plain go
	verified := merkletree.VerifyProof(utils.DefaultHasher(), rootHash, proofPath, idx, numLeaves)
	if !verified {
		panic("the merkle proof in plain go should pass")
	}

	var assignment types.ZKCircuit
	assignment.SetCurveId(ecc_tedwards.BN254)
	assignment.FromPrv0, assignment.FromPrv1 = w.getPrvScalar()
	assignment.NoteVer = noteSpent.Version
	assignment.FromPub.Assign(assignment.GetCurveId(), noteSpent.PubKey.Bytes())
	assignment.Balance = noteSpent.Balance.Bytes()
	assignment.Salt0 = noteSpent.Salt
	assignment.NoteCommitment = noteCommitment
	assignment.NoteIdx = idx
	assignment.NoteMerkleRoot = rootHash
	assignment.NoteMerklePath = make([]frontend.Variable, depth+1)
	for i := 0; i < len(assignment.NoteMerklePath); i++ {
		if i < len(proofPath) {
			assignment.NoteMerklePath[i] = proofPath[i]
			fmt.Printf("proofPath[%d]=%s\n", i, new(uint256.Int).SetBytes(proofPath[i]).Dec())
		} else {
			assignment.NoteMerklePath[i] = 0
		}
	}
	// Amount와 Fee도 field element로 할당
	assignment.Amount = amt.Bytes()
	assignment.Fee = fee.Bytes()
	assignment.ToPub.Assign(assignment.GetCurveId(), toPubKey.Bytes())
	assignment.Salt1 = salt1
	assignment.NewNoteCommitment = newNote.Commitment()
	assignment.ChangeNoteCommitment = changeNote.Commitment()
	prv0, prv1 := w.getPrvScalar()
	assignment.Nullifier = noteSpent.Nullifier(prv0, prv1)

	wtn, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	fmt.Printf("---- NewWitness..OK\n")

	proof, err := plonk.Prove(
		ccs,
		types.ProvingKey,
		wtn,
		backend.WithSolverOptions(
			solver.WithLogger(gnarkLogger),
		),
	)

	fmt.Printf("---- Prove=%s\n", proof)

	if err != nil {
		panic(err)
	}
	return proof
}

var gnarkLogger = zerolog.New(os.Stdout).Level(zerolog.TraceLevel).With().Timestamp().Logger()
