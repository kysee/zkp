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

	// todo: Verify zktx.MerkleRoot
	// the below is a temporary solution.
	// when zktx was made, the merkle root hash may be different from the latest one (`noteCommitmentsRoot`).
	tmpAssignment := types.ZKCircuit{
		NoteMerkleRoot:       noteCommitmentsRoot, // don't use the zktx.MerkleRoot; it may be faked.
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

	addNoteNullifier(zktx.Nullifier)
	addNoteCommitment(zktx.NewNoteCommitment)
	addNoteCommitment(zktx.ChangeNoteCommitment)
	addSecretNote(zktx.NewSecretNote)
	addSecretNote(zktx.NewChangeSecretNote)
	return nil
}

//
// For Merkle Tree
//

func GetNoteCommitment(idx int) types.NoteCommitment {
	ret := make([]byte, len(noteCommitments[idx]))
	copy(ret, noteCommitments[idx])
	return ret
}

func GetNoteCommitmentMerkle(commitment types.NoteCommitment) (root []byte, proofSet [][]byte, depth int, idx, numLeaves uint64, err error) {
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
