package common

import (
	"bytes"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/kysee/zkp/utils"
)

type NoteCommitment []byte
type NoteNullifier []byte

var (
	noteMerkleDepth     = 32
	noteCommitmentsRoot []byte
	noteCommitmentsTree = merkletree.New(utils.DefaultHasher())
	noteCommitments     []NoteCommitment
	noteNullifiers      []NoteNullifier
)

func AddNoteCommitment(commitment NoteCommitment) int {
	//fmt.Printf("AddNoteCommitment: %x\n", commitment)
	noteCommitments = append(noteCommitments, commitment)
	noteCommitmentsTree.Push(commitment)
	noteCommitmentsRoot = noteCommitmentsTree.Root()

	return len(noteCommitments) - 1
}

func GetNoteCommitment(idx int) NoteCommitment {
	ret := make([]byte, len(noteCommitments[idx]))
	copy(ret, noteCommitments[idx])
	return ret
}

func GetNoteCommitmentMerkle(commitment NoteCommitment) (root []byte, proofSet [][]byte, idx, depth, numLeaves uint64, err error) {
	var buf bytes.Buffer
	for i, c := range noteCommitments {
		if bytes.Equal(c, commitment) {
			idx = uint64(i)
		}
		buf.Write(c)
	}
	root, proofSet, numLeaves, err = merkletree.BuildReaderProof(
		&buf,
		utils.DefaultHasher(),
		utils.DefaultHasher().Size(),
		idx,
	)
	depth = uint64(noteMerkleDepth)
	return
}

func GetNoteCommitmentsRoot() []byte {
	ret := make([]byte, len(noteCommitmentsRoot))
	copy(ret, noteCommitmentsRoot)
	return ret
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
