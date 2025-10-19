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
		NoteMerkleRoot:       noteCommitmentsRoot, // use the note's root. not the zktx's root.
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
	AddNoteCommitment(zktx.ChangeNoteCommitment)
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

func GetNoteCommitmentMerkle(commitment NoteCommitment) (root []byte, proofSet [][]byte, depth int, idx, numLeaves uint64, err error) {
	var buf bytes.Buffer
	found := false
	for i, c := range noteCommitments {
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

func GetNoteCommitmentsRoot() []byte {
	ret := make([]byte, len(noteCommitmentsRoot))
	copy(ret, noteCommitmentsRoot)
	return ret
}

func GetNoteCommitmentMerkleDepth() int {
	return noteMerkleDepth
}
