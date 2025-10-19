package types

type ZKTx struct {
	ProofBytes           []byte
	MerkleRoot           []byte
	Nullifier            []byte
	NewNoteCommitment    []byte
	ChangeNoteCommitment []byte
}
