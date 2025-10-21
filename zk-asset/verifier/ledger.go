package verifier

import (
	"bytes"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-asset/types"
)

// Merkle tree depth - circuit compile 시 사용한 depth와 동일해야 함
// depth=20: 2^20 = 1,048,576 leaves 지원
// depth=32: 2^32 = 4,294,967,296 leaves 지원 (하지만 circuit 크기가 매우 커짐)
const noteMerkleDepth = 32

var (
	zkCircuit      constraint.ConstraintSystem
	ZKProvingKey   plonk.ProvingKey
	ZKVerifyingKey plonk.VerifyingKey

	noteCommitmentsTree *merkletree.Tree
	noteCommitmentsRoot []byte
	noteCommitments     []types.NoteCommitment
	noteNullifiers      []types.NoteNullifier
)

func init() {
	noteCommitmentsTree = merkletree.New(utils.MiMCHasher())
	zkCircuit, ZKProvingKey, ZKVerifyingKey = types.CompileCircuit(noteMerkleDepth)
}

func InitMint(addr string, amount *uint256.Int) {
	// initial minting...

	salt := types.RandBytes(32)

	pubKey := types.Addr2Pub(addr)
	note := &types.Note{
		Version: 1,
		PubKey:  pubKey,
		Balance: amount,
		Salt:    salt,
	}
	addNoteCommitment(note.Commitment())

	sharedNote := &types.SharedNote{
		Version: 1,
		Balance: amount,
		Salt:    salt,
		Memo:    nil,
	}

	//
	// Encrypt the SharedNote

	secretNote, err := types.EncryptSharedNote(sharedNote, nil, pubKey)
	if err != nil {
		panic(err)
	}
	addSecretNote(secretNote)
}

func addNoteCommitment(commitment types.NoteCommitment) int {
	//fmt.Printf("addNoteCommitment: %x\n", commitment)
	noteCommitments = append(noteCommitments, commitment)
	noteCommitmentsTree.Push(commitment)
	noteCommitmentsRoot = noteCommitmentsTree.Root()

	return len(noteCommitments) - 1
}

func addNoteNullifier(nullifier types.NoteNullifier) {
	noteNullifiers = append(noteNullifiers, nullifier)
}

func FindNoteNullifier(nullifier types.NoteNullifier) types.NoteNullifier {
	for _, n := range noteNullifiers {
		if bytes.Equal(n, nullifier) {
			ret := make([]byte, len(n))
			copy(ret, n)
			return ret
		}
	}
	return nil
}

func VerifyNoteCommitmentProof(commitment types.NoteCommitment, root []byte, idx uint64) bool {
	// Build the proof from scratch for verification
	var buf bytes.Buffer
	for _, c := range noteCommitments {
		buf.Write(c)
	}
	vRoot, vProof, vNumLeaves, err := merkletree.BuildReaderProof(
		&buf,
		utils.DefaultHasher(),
		utils.DefaultHasher().Size(),
		idx,
	)
	if err != nil {
		return false
	}
	if !bytes.Equal(vRoot, root) {
		return false
	}
	return merkletree.VerifyProof(utils.DefaultHasher(), vRoot, vProof, idx, vNumLeaves)
}

// for secret notes
var ledgerSecretNotes [][]byte // [ECDHE public key | ciphertext]

func addSecretNote(enc []byte) {
	ledgerSecretNotes = append(ledgerSecretNotes, enc)
}

func GetSecretNote(idx int) []byte {
	if idx < len(ledgerSecretNotes) {
		return ledgerSecretNotes[idx]
	}
	return nil
}
