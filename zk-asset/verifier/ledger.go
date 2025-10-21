package verifier

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

	merkleNoteCommitments *merkletree.Tree
	ledgerNoteCommitments []types.NoteCommitment
	ledgerNoteNullifiers  []types.NoteNullifier
)

func init() {
	merkleNoteCommitments = merkletree.New(utils.MiMCHasher())
	zkCircuit, ZKProvingKey, ZKVerifyingKey = types.CompileCircuit(noteMerkleDepth)
}

func InitMint(addr string, amount *uint256.Int) {
	// initial minting...

	zktx := types.NewZKTx()
	salt := types.RandBytes(32)

	pubKey := types.Addr2Pub(addr)
	note := &types.Note{
		Version: 1,
		PubKey:  pubKey,
		Balance: amount,
		Salt:    salt,
	}
	zktx.NewNoteCommitments[0] = note.Commitment()
	addNoteCommitment(zktx.NewNoteCommitments[0])

	sharedNote := &types.SharedNote{
		Version: 1,
		Balance: amount,
		Salt:    salt,
		Memo:    nil,
	}

	//
	// Encrypt the SharedNote

	secretNote, err := types.EncryptSharedNote(sharedNote, nil, pubKey)
	if err != nil {
		panic(err)
	}
	zktx.NewSecretNotes[0] = secretNote
	addSecretNote(zktx.NewSecretNotes[0])

	addZKTx(zktx)
}

func addNoteCommitment(commitment types.NoteCommitment) int {
	//fmt.Printf("addNoteCommitment: %x\n", commitment)
	ledgerNoteCommitments = append(ledgerNoteCommitments, commitment)
	merkleNoteCommitments.Push(commitment)

	return len(ledgerNoteCommitments) - 1
}

func addNoteNullifier(nullifier types.NoteNullifier) {
	ledgerNoteNullifiers = append(ledgerNoteNullifiers, nullifier)
}

func FindNoteNullifier(nullifier types.NoteNullifier) types.NoteNullifier {
	for _, n := range ledgerNoteNullifiers {
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
	for _, c := range ledgerNoteCommitments {
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
var ledgerSecretNotes [][]byte // [ECDHE public key | ciphertext]

func addSecretNote(enc []byte) {
	ledgerSecretNotes = append(ledgerSecretNotes, enc)
}

func GetSecretNote(idx int) []byte {
	if idx < len(ledgerSecretNotes) {
		return ledgerSecretNotes[idx]
	}
	return nil
}

// for ZKTx
var ledgerZKTx []*types.ZKTx

func addZKTx(zkTx *types.ZKTx) {
	ledgerZKTx = append(ledgerZKTx, zkTx)
}

func GetZKTx(idx int) *types.ZKTx {
	if idx < len(ledgerZKTx) {
		return ledgerZKTx[idx]
	}
	return nil
}
