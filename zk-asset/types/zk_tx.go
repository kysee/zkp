package types

type ZKTx struct {
	ProofBytes           []byte
	MerkleRoot           []byte
	Nullifier            []byte
	ChangeNoteCommitment []byte
	NewNoteCommitment    []byte
	EncryptedSecretNote  []byte
}
