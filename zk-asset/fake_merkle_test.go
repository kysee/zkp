package zk_asset

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-asset/node"
	"github.com/kysee/zkp/zk-asset/types"
	"github.com/kysee/zkp/zk-asset/wallet"
	"github.com/stretchr/testify/require"
)

func TestFakeMerkle_WrongRootHash(t *testing.T) {
	sender := wallet.Wallets[0]
	receiver := wallet.Wallets[5]
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	useSharedNote := sender.GetSharedNote(0)
	useNote := useSharedNote.ToNoteOf(sender.PrivateKey.Public())
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

func TestFakeMerkle_NonExistNote(t *testing.T) {
	sender := wallet.Wallets[0]
	receiver := wallet.Wallets[5]
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	nonExistNote := &types.Note{
		Version: 1,
		PubKey:  sender.PrivateKey.Public(),
		Balance: uint256.NewInt(1_000_000),
		Salt:    types.RandBytes(32),
	}

	// get merkle proof info for the existing note.
	existNote := sender.GetSharedNote(0).ToNoteOf(sender.PrivateKey.Public())
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

func TestFakeMerkle_UseFakeMerkle(t *testing.T) {
	faker := wallet.NewWallet()

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

		sharedNote := &types.SharedNote{
			Version: 1,
			Balance: balance,
			Salt:    salt,
			Memo:    nil,
		}
		faker.AddSharedNote(sharedNote)
	}

	receiver := wallet.NewWallet()
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	useSharedNote := faker.GetSharedNote(0)
	useNote := useSharedNote.ToNoteOf(faker.PrivateKey.Public())
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
