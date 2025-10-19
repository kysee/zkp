package zk_asset

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-asset/node"
	"github.com/kysee/zkp/zk-asset/types"
	"github.com/stretchr/testify/require"
)

var (
	css     constraint.ConstraintSystem
	prKey   plonk.ProvingKey
	wallets []*Wallet
)

func init() {
	css, prKey, _ = types.CompileCircuit(node.GetNoteCommitmentMerkleDepth())

	for i := 0; i < 10; i++ {
		wallets = append(wallets, NewWallet())
	}

	for i := 0; i < 5; i++ {
		balance := uint256.NewInt(100)
		salt := types.RandBytes(32)

		note := &types.Note{
			Version: 1,
			PubKey:  wallets[i].PrivateKey.Public(),
			Balance: balance,
			Salt:    salt,
		}
		node.AddNoteCommitment(note.Commitment())

		secretNote := &types.SecretNote{
			Version: 1,
			Balance: balance,
			Salt:    salt,
			Memo:    nil,
		}
		wallets[i].AddSecretNote(secretNote)
	}
}

func TestTransfer(t *testing.T) {
	sender := wallets[0]
	receiver := wallets[5]
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	senderBalance0 := sender.GetBalance()
	recieverBalance0 := receiver.GetBalance()

	useSecretNote := sender.GetSecretNote(0)
	useNote := useSecretNote.ToNoteOf(sender.PrivateKey.Public())
	useNoteCommitment := useNote.Commitment()

	// get merkle proof info.
	rootHash, proofPath, depth, idx, _, err := node.GetNoteCommitmentMerkle(useNoteCommitment)
	require.NoError(t, err)
	//fmt.Printf("Merkle Info: numLeaves=%d, idx=%d, depth=%d, proofPath.len=%d\n", numLeaves, idx, depth, len(proofPath))

	// generate the ZKTx including zk-proof
	zkTx, newNotes, err := sender.TransferProof(
		receiver.Address, amt, fee,
		useNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	require.NoError(t, err)
	fmt.Printf("proof      : (%4dB) %x\n", len(zkTx.ProofBytes), zkTx.ProofBytes)
	fmt.Printf("merkle root: (%4dB) %x\n", len(zkTx.MerkleRoot), zkTx.MerkleRoot)
	fmt.Printf("nullifier  : (%4dB) %x\n", len(zkTx.Nullifier), zkTx.Nullifier)
	fmt.Printf("newNote    : (%4dB) %x\n", len(zkTx.NewNoteCommitment), zkTx.NewNoteCommitment)
	fmt.Printf("changeNote : (%4dB) %x\n", len(zkTx.ChangeNoteCommitment), zkTx.ChangeNoteCommitment)

	// send the ZKTx to the node
	err = node.SendZKTransaction(zkTx)
	require.NoError(t, err)

	fmt.Println("---")

	sender.DelSecretNote(useSecretNote)
	sender.AddSecretNote(newNotes[1].ToSecretNote()) // for change
	receiver.AddSecretNote(newNotes[0].ToSecretNote())

	senderBalance1 := sender.GetBalance()
	recieverBalance1 := receiver.GetBalance()
	require.EqualValues(t, new(uint256.Int).Sub(senderBalance0, new(uint256.Int).Add(amt, fee)), senderBalance1)
	require.EqualValues(t, new(uint256.Int).Add(recieverBalance0, amt), recieverBalance1)

	fmt.Println("sender balance  : ", senderBalance0.Dec(), ">", senderBalance1.Dec())
	fmt.Println("receiver balance: ", recieverBalance0.Dec(), ">", recieverBalance1.Dec())
}

func Test_Nullifier(t *testing.T) {
}

func TestTransfer_WrongMerkleRootHash(t *testing.T) {
	sender := wallets[0]
	receiver := wallets[5]
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	useSecretNote := sender.GetSecretNote(0)
	useNote := useSecretNote.ToNoteOf(sender.PrivateKey.Public())
	useNoteCommitment := useNote.Commitment()

	// get merkle proof info.
	rootHash, proofPath, depth, idx, _, err := node.GetNoteCommitmentMerkle(useNoteCommitment)
	require.NoError(t, err)
	//fmt.Printf("Merkle Info: numLeaves=%d, idx=%d, depth=%d, proofPath.len=%d\n", numLeaves, idx, depth, len(proofPath))

	// modifies the rootHash
	rootHash[0], rootHash[1] = rootHash[1], rootHash[0]

	// generate the ZKTx including zk-proof
	_, _, err = sender.TransferProof(
		receiver.Address, amt, fee,
		useNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	require.Error(t, err)
}

func TestTransfer_NonExistNote(t *testing.T) {
	sender := wallets[0]
	receiver := wallets[5]
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	nonExistNote := &types.Note{
		Version: 1,
		PubKey:  sender.PrivateKey.Public(),
		Balance: uint256.NewInt(1_000_000),
		Salt:    types.RandBytes(32),
	}

	// get merkle proof info for the existing note.
	existNote := sender.GetSecretNote(0).ToNoteOf(sender.PrivateKey.Public())
	rootHash, proofPath, depth, idx, numLeaves, err := node.GetNoteCommitmentMerkle(existNote.Commitment())
	require.NoError(t, err)
	fmt.Printf("Merkle Info: numLeaves=%d, idx=%d, depth=%d, proofPath.len=%d\n", numLeaves, idx, depth, len(proofPath))

	// expected error: nonExistNote.Commitment() is not in the proofPath
	_, _, err = sender.TransferProof(
		receiver.Address, amt, fee,
		nonExistNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	require.Error(t, err)

	// make the proofPath have the nonExistNote.Commitment()
	proofPath[0] = nonExistNote.Commitment()

	// expected error: rootHash is not same
	_, _, err = sender.TransferProof(
		receiver.Address, amt, fee,
		nonExistNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	require.Error(t, err)
}

var fakeMerkleTree = merkletree.New(utils.MiMCHasher())
var fakeCommitmentsRoot []byte
var fakeCommitments []types.NoteCommitment
var fakeMerkleDepth = node.GetNoteCommitmentMerkleDepth()

func TestTransfer_FakeMerkle(t *testing.T) {
	faker := NewWallet()

	for i := 0; i < 5; i++ {
		balance := uint256.NewInt(1_000_000_000)
		salt := types.RandBytes(32)

		fakeNote := &types.Note{
			Version: 1,
			PubKey:  faker.PrivateKey.Public(),
			Balance: balance,
			Salt:    salt,
		}
		commitment := fakeNote.Commitment()
		fakeCommitments = append(fakeCommitments, commitment)
		fakeMerkleTree.Push(commitment)
		fakeCommitmentsRoot = fakeMerkleTree.Root()

		secretNote := &types.SecretNote{
			Version: 1,
			Balance: balance,
			Salt:    salt,
			Memo:    nil,
		}
		faker.AddSecretNote(secretNote)
	}

	receiver := NewWallet()
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	useSecretNote := faker.GetSecretNote(0)
	useNote := useSecretNote.ToNoteOf(faker.PrivateKey.Public())
	useNoteCommitment := useNote.Commitment()

	// get merkle proof info.
	rootHash, proofPath, depth, idx, numLeaves, err := getFakeCommitmentMerklePaths(useNoteCommitment)
	require.NoError(t, err)
	fmt.Printf("Merkle Info: numLeaves=%d, idx=%d, depth=%d, proofPath.len=%d\n", numLeaves, idx, depth, len(proofPath))

	// generate the ZKTx including zk-proof
	zkTx, _, err := faker.TransferProof(
		receiver.Address, amt, fee,
		useNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	// the merkle tree is fully faked.
	// so, the proof generation by TransferProof is succeeded.
	require.NoError(t, err)
	// expected error: the zkTx.MerkleRoot is different from the merkle root hash of the node.
	err = node.SendZKTransaction(zkTx)
	require.Error(t, err)
}

func getFakeCommitmentMerklePaths(commitment types.NoteCommitment) (root []byte, proofSet [][]byte, depth int, idx, numLeaves uint64, err error) {
	var buf bytes.Buffer
	found := false
	for i, c := range fakeCommitments {
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
	depth = fakeMerkleDepth
	return
}
