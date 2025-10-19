package node

import (
	"bytes"
	"errors"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-asset/types"
)

func SendZKTransaction(zktx *types.ZKTx) error {
	// verify zk proof and handdles nullifier, new note commitments

	if FindNoteNullifier(zktx.Nullifier) != nil {
		return errors.New("nullifier already exists")
	}

	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewBuffer(zktx.ProofBytes)); err != nil {
		return err
	}

	tmpAssignment := types.ZKCircuit{
		NoteMerkleRoot:       zktx.MerkleRoot,
		Nullifier:            zktx.Nullifier,
		NewNoteCommitment:    zktx.NewNoteCommitment,
		ChangeNoteCommitment: zktx.ChangeNoteCommitment,
	}
	pubWtn, err := frontend.NewWitness(&tmpAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	err = plonk.Verify(proof, ZKVerifyingKey, pubWtn)
	if err != nil {
		return err
	}

	AddNoteNullifier(zktx.Nullifier)
	AddNoteCommitment(zktx.NewNoteCommitment)
	return nil
}

//
// For Merkle Tree
//

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
	if err != nil {
		return
	}
	depth = uint64(noteMerkleDepth)
	return
}

func GetNoteCommitmentsRoot() []byte {
	ret := make([]byte, len(noteCommitmentsRoot))
	copy(ret, noteCommitmentsRoot)
	return ret
}

func GetNoteCommitmentMerkleDepth() int {
	return noteMerkleDepth
}
