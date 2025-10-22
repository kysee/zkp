package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/zk-asset/prover"
	"github.com/kysee/zkp/zk-asset/types"
)

// ProofData represents the proof data to be sent to the smart contract
type ProofData struct {
	Proof        []string `json:"proof"`        // Hex encoded proof
	PublicInputs []string `json:"publicInputs"` // [merkleRoot, nullifier, newNoteCommitment, changeNoteCommitment]
}

// TransferParams contains all parameters needed for a transfer
type TransferParams struct {
	// Source note (being spent)
	FromPrivateKey signature.Signer
	FromNote       *types.Note
	NoteIndex      uint64
	MerklePath     [][]byte
	MerkleRoot     []byte

	// Transfer details
	ToAddr string
	Amount *uint256.Int
	Fee    *uint256.Int

	// New salts for notes
	NewNoteSalt    []byte
	ChangeNoteSalt []byte
}

// GenerateTransferProof generates a ZK proof for asset transfer using existing prover
func GenerateTransferProof(params *TransferParams) (*ProofData, error) {
	const depth = 5

	// Compile circuit to get proving key and constraint system
	ccs, pk, _ := types.CompileCircuit(depth)

	// Get destination public key
	toPubKey := types.Addr2Pub(params.ToAddr)

	// Create new note with the specified salt
	newNote := &types.Note{
		Version: params.FromNote.Version,
		PubKey:  toPubKey,
		Balance: params.Amount,
		Salt:    params.NewNoteSalt,
	}

	// Create change note
	change := new(uint256.Int).Sub(params.FromNote.Balance, params.Amount)
	change.Sub(change, params.Fee)

	changeNote := &types.Note{
		Version: params.FromNote.Version,
		PubKey:  params.FromNote.PubKey,
		Balance: change,
		Salt:    params.ChangeNoteSalt,
	}

	// Use existing CreateZKProof function
	proofBytes, nullifier, newNoteC, changeNoteC, err := prover.CreateZKProof(
		params.FromPrivateKey,
		toPubKey, params.Amount, params.Fee,
		params.MerkleRoot, params.MerklePath, depth, params.NoteIndex,
		params.FromNote, newNote, changeNote,
		pk, ccs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	// Convert to Solidity format
	proofData := &ProofData{
		Proof: []string{fmt.Sprintf("0x%x", proofBytes)},
		PublicInputs: []string{
			fmt.Sprintf("0x%x", params.MerkleRoot),
			fmt.Sprintf("0x%x", nullifier),
			fmt.Sprintf("0x%x", newNoteC),
			fmt.Sprintf("0x%x", changeNoteC),
		},
	}

	return proofData, nil
}
