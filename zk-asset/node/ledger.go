package node

import (
	"bytes"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-asset/types"
)

// Merkle tree depth - circuit compile 시 사용한 depth와 동일해야 함
// depth=20: 2^20 = 1,048,576 leaves 지원
// depth=32: 2^32 = 4,294,967,296 leaves 지원 (하지만 circuit 크기가 매우 커짐)
const noteMerkleDepth = 32

var (
	zkCircuit      constraint.ConstraintSystem
	ZKProvingKey   plonk.ProvingKey
	ZKVerifyingKey plonk.VerifyingKey

	noteCommitmentsTree *merkletree.Tree
	noteCommitmentsRoot []byte
	noteCommitments     []types.NoteCommitment
	noteNullifiers      []types.NoteNullifier
)

func init() {
	noteCommitmentsTree = merkletree.New(utils.MiMCHasher())
	zkCircuit, ZKProvingKey, ZKVerifyingKey = types.CompileCircuit(noteMerkleDepth)

	// initial minting...
	for i := 0; i < 100; i++ {
		balance := uint256.NewInt(100)
		salt := types.RandBytes(32)

		w := types.NewWallet()
		types.Wallets = append(types.Wallets, w)

		note := &types.Note{
			Version: 1,
			PubKey:  w.PrivateKey.Public(),
			Balance: balance,
			Salt:    salt,
		}
		AddNoteCommitment(note.Commitment())

		secretNote := &types.SecretNote{
			Version: 1,
			Balance: balance,
			Salt:    salt,
			Memo:    nil,
		}

		//
		// Encrypt the SecretNote

		encSecretNote, bzPubKey, err := types.EncryptSecretNote(secretNote, nil, w.PrivateKey.Public())
		if err != nil {
			panic(err)
		}
		AddEncryptedSecretNote(append(bzPubKey, encSecretNote...))
	}
}

func AddNoteCommitment(commitment types.NoteCommitment) int {
	//fmt.Printf("AddNoteCommitment: %x\n", commitment)
	noteCommitments = append(noteCommitments, commitment)
	noteCommitmentsTree.Push(commitment)
	noteCommitmentsRoot = noteCommitmentsTree.Root()

	return len(noteCommitments) - 1
}

func AddNoteNullifier(nullifier types.NoteNullifier) {
	noteNullifiers = append(noteNullifiers, nullifier)
}

func FindNoteNullifier(nullifier types.NoteNullifier) types.NoteNullifier {
	for _, n := range noteNullifiers {
		if bytes.Equal(n, nullifier) {
			ret := make([]byte, len(n))
			copy(ret, n)
			return ret
		}
	}
	return nil
}

func VerifyNoteCommitmentProof(commitment types.NoteCommitment, root []byte, idx uint64) bool {
	// Build the proof from scratch for verification
	var buf bytes.Buffer
	for _, c := range noteCommitments {
		buf.Write(c)
	}
	vRoot, vProof, vNumLeaves, err := merkletree.BuildReaderProof(
		&buf,
		utils.DefaultHasher(),
		utils.DefaultHasher().Size(),
		idx,
	)
	if err != nil {
		return false
	}
	if !bytes.Equal(vRoot, root) {
		return false
	}
	return merkletree.VerifyProof(utils.DefaultHasher(), vRoot, vProof, idx, vNumLeaves)
}

// for secret notes
var encryptedSecretNotes [][]byte // [ECDHE public key | ciphertext]

func AddEncryptedSecretNote(enc []byte) {
	encryptedSecretNotes = append(encryptedSecretNotes, enc)
}

func GetEncryptedSecretNote(idx int) []byte {
	if idx < len(encryptedSecretNotes) {
		return encryptedSecretNotes[idx]
	}
	return nil
}
