package prover

import (
	"bytes"
	crand "crypto/rand"

	"github.com/consensys/gnark-crypto/ecc"
	ecc_tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/zk-asset/types"
)

// CreateZKTx generates proof and returns `*ZKTx`
func CreateZKTx(
	signer signature.Signer,
	toAddr string, amt, fee *uint256.Int,
	usedNote *types.Note,
	rootHash []byte, proofPath [][]byte, depth int, idx uint64,
	provingKey plonk.ProvingKey, ccs constraint.ConstraintSystem,
) (*types.ZKTx, error) {

	toPubKey := types.Addr2Pub(toAddr)

	salt1 := make([]byte, 32)
	crand.Read(salt1)

	newNote := &types.Note{
		Version: 1,
		PubKey:  toPubKey,
		Balance: amt,
		Salt:    salt1,
	}
	newSecretNote, err := types.EncryptSharedNote(newNote.ToSharedNote(), nil, toPubKey)

	changeNote := &types.Note{
		Version: 1,
		PubKey:  usedNote.PubKey,
		Balance: new(uint256.Int).Sub(usedNote.Balance, new(uint256.Int).Add(amt, fee)),
		Salt:    usedNote.Salt,
	}
	newChangeSecretNote, err := types.EncryptSharedNote(changeNote.ToSharedNote(), nil, signer.Public())

	bzProof, nullifier, newNoteC, changeNoteC, err := CreateZKProof(
		signer,
		toPubKey, amt, fee,
		rootHash, proofPath, depth, idx,
		usedNote, newNote, changeNote,
		provingKey, ccs)
	if err != nil {
		return nil, err
	}

	return &types.ZKTx{
		ProofBytes:         bzProof,
		MerkleRoot:         rootHash,
		Nullifier:          nullifier,
		NewNoteCommitments: []types.NoteCommitment{newNoteC, changeNoteC},
		NewSecretNotes:     []types.SecretNote{newSecretNote, newChangeSecretNote},
	}, nil
}

func CreateZKProof(
	signer signature.Signer,
	toPubKey signature.PublicKey, amt, fee *uint256.Int,
	rootHash []byte, proofPath [][]byte, depth int, idx uint64,
	usedNote, newNote, changeNote *types.Note,
	provingKey plonk.ProvingKey, ccs constraint.ConstraintSystem,
) ([]byte, []byte, []byte, []byte, error) {

	s := signer.Bytes()[32:64]
	prv0, prv1 := s[:16], s[16:32]

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
	assignment.NoteCommitment = usedNote.Commitment()
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
	assignment.Salt1 = newNote.Salt
	assignment.NewNoteCommitment = newNoteC
	assignment.ChangeNoteCommitment = changeNoteC
	assignment.Nullifier = nullifier

	wtn, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	proof, err := plonk.Prove(
		ccs,
		provingKey,
		wtn,
		//backend.WithSolverOptions(
		//	solver.WithLogger(
		//zerolog.New(os.Stdout).Level(zerolog.TraceLevel).With().Timestamp().Logger()
		//	),
		//),
	)

	if err != nil {
		return nil, nil, nil, nil, err
	}

	bufProof := bytes.NewBuffer(nil)
	if _, err := proof.WriteTo(bufProof); err != nil {
		return nil, nil, nil, nil, err
	}
	return bufProof.Bytes(), nullifier, newNoteC, changeNoteC, nil
}
