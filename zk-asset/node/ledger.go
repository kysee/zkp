package node

import (
	"bytes"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-asset/types"
)

type NoteCommitment []byte
type NoteNullifier []byte

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
	noteCommitments     []NoteCommitment
	noteNullifiers      []NoteNullifier
)

func init() {
	noteCommitmentsTree = merkletree.New(utils.MiMCHasher())
	zkCircuit, ZKProvingKey, ZKVerifyingKey = types.CompileCircuit(noteMerkleDepth)
}

func AddNoteCommitment(commitment NoteCommitment) int {
	//fmt.Printf("AddNoteCommitment: %x\n", commitment)
	noteCommitments = append(noteCommitments, commitment)
	noteCommitmentsTree.Push(commitment)
	noteCommitmentsRoot = noteCommitmentsTree.Root()

	return len(noteCommitments) - 1
}

func AddNoteNullifier(nullifier NoteNullifier) {
	noteNullifiers = append(noteNullifiers, nullifier)
}

func FindNoteNullifier(nullifier NoteNullifier) NoteNullifier {
	for _, n := range noteNullifiers {
		if bytes.Equal(n, nullifier) {
			ret := make([]byte, len(n))
			copy(ret, n)
			return ret
		}
	}
	return nil
}

func VerifyNoteCommitmentProof(commitment NoteCommitment, root []byte, idx uint64) bool {
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
