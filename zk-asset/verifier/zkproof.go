package verifier

import (
	"bytes"
	"errors"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/kysee/zkp/zk-asset/types"
)

func VerifyZKTx(zktx *types.ZKTx) error {

	if err := VerifyZKProof(
		zktx.ProofBytes,
		noteCommitmentsRoot,
		zktx.Nullifier,
		zktx.NewNoteCommitments); err != nil {
		return err
	}

	addNoteNullifier(zktx.Nullifier)
	addNoteCommitment(zktx.NewNoteCommitments[0])
	addNoteCommitment(zktx.NewNoteCommitments[1])
	addSecretNote(zktx.NewSecretNotes[0])
	addSecretNote(zktx.NewSecretNotes[1])
	addZKTx(zktx)
	return nil
}

func VerifyZKProof(bzProof []byte, merkleRootHash, nullifier []byte, newCommitments [][]byte) error {
	// verify zk proof and handdles nullifier, new note commitments

	if FindNoteNullifier(nullifier) != nil {
		return errors.New("nullifier already exists")
	}

	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewBuffer(bzProof)); err != nil {
		return err
	}

	// todo: Verify zktx.MerkleRoot
	// the below is a temporary solution.
	// when zktx was made, the merkle root hash may be different from the latest one (`noteCommitmentsRoot`).
	tmpAssignment := types.ZKCircuit{
		NoteMerkleRoot:       merkleRootHash, // don't use the zktx.MerkleRoot; it may be faked.
		Nullifier:            nullifier,
		NewNoteCommitment:    newCommitments[0],
		ChangeNoteCommitment: newCommitments[1],
	}
	pubWtn, err := frontend.NewWitness(&tmpAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return plonk.Verify(proof, ZKVerifyingKey, pubWtn)
}
