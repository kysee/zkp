package types

type ZKTx struct {
	ProofBytes           []byte
	MerkleRoot           []byte
	Nullifier            []byte
	ChangeNoteCommitment []byte
	NewNoteCommitment    []byte
	NewSecretNote        []byte
	NewChangeSecretNote  []byte
}
