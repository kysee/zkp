package types

type ZKTx struct {
	ProofBytes         []byte
	MerkleRoot         []byte
	Nullifier          NoteNullifier
	NewNoteCommitments []NoteCommitment
	NewSecretNotes     [][]byte
}

func NewZKTx() *ZKTx {
	return &ZKTx{
		NewNoteCommitments: make([]NoteCommitment, 2),
		NewSecretNotes:     make([][]byte, 2),
	}
}
