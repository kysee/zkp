package verifier

import (
	"bytes"
	"errors"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-asset/types"
)

//
// For Merkle Tree
//

func GetNoteCommitment(idx int) types.NoteCommitment {
	ret := make([]byte, len(ledgerNoteCommitments[idx]))
	copy(ret, ledgerNoteCommitments[idx])
	return ret
}

func GetNoteCommitmentMerkle(commitment types.NoteCommitment) (root []byte, proofSet [][]byte, depth int, idx, numLeaves uint64, err error) {
	var buf bytes.Buffer
	found := false
	for i, c := range ledgerNoteCommitments {
		if bytes.Equal(c, commitment) {
			idx = uint64(i)
			found = true
		}
		buf.Write(c)
	}
	if !found {
		err = errors.New("commitment not found")
		return
	}
	root, proofSet, numLeaves, err = merkletree.BuildReaderProof(
		&buf,
		utils.DefaultHasher(),
		utils.DefaultHasher().Size(),
		idx,
	)
	if err != nil {
		return
	}
	depth = noteMerkleDepth
	return
}

func GetNoteCommitmentMerkleDepth() int {
	return noteMerkleDepth
}
