package zk_asset

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/holiman/uint256"
	"github.com/kysee/zkp/zk-asset/prover"
	"github.com/kysee/zkp/zk-asset/types"
	"github.com/kysee/zkp/zk-asset/verifier"
	"github.com/stretchr/testify/require"
)

var (
	css   constraint.ConstraintSystem
	prKey plonk.ProvingKey
)

func init() {

	// reconstruct the constraint system from the circuit compiled in the verifier

	buf := bytes.NewBuffer(nil)
	if _, err := verifier.ZKCSS.WriteTo(buf); err != nil {
		panic(err)
	}

	var _css cs_bn254.SparseR1CS
	if _, err := _css.ReadFrom(buf); err != nil {
		panic(err)
	}

	css = &_css
	prKey = verifier.ZKProvingKey
}

func TestTransfer(t *testing.T) {
	sender := prover.Wallets[0]
	receiver := prover.Wallets[5]
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	senderBalance0 := sender.GetBalance()
	recieverBalance0 := receiver.GetBalance()

	useSharedNote := sender.GetSharedNote(0)
	useNote := useSharedNote.ToNoteOf(sender.PrivateKey.Public())
	useNoteCommitment := useNote.Commitment()

	// get merkle proof info.
	rootHash, proofPath, depth, idx, _, err := verifier.GetNoteCommitmentMerkle(useNoteCommitment)
	require.NoError(t, err)
	//fmt.Printf("Merkle Info: numLeaves=%d, idx=%d, depth=%d, proofPath.len=%d\n", numLeaves, idx, depth, len(proofPath))

	// generate the ZKTx including zk-proof
	zkTx, err := prover.CreateZKTx(
		sender.PrivateKey,
		receiver.Address, amt, fee,
		useNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	require.NoError(t, err)
	fmt.Printf("proof      : (%4dB) %x\n", len(zkTx.ProofBytes), zkTx.ProofBytes)
	fmt.Printf("merkle root: (%4dB) %x\n", len(zkTx.MerkleRoot), zkTx.MerkleRoot)
	fmt.Printf("nullifier  : (%4dB) %x\n", len(zkTx.Nullifier), zkTx.Nullifier)
	fmt.Printf("newNote    : (%4dB) %x\n", len(zkTx.NewNoteCommitments[0]), zkTx.NewNoteCommitments[0])
	fmt.Printf("changeNote : (%4dB) %x\n", len(zkTx.NewNoteCommitments[1]), zkTx.NewNoteCommitments[1])

	// send the ZKTx to the verifier
	err = verifier.VerifyZKTx(zkTx)
	require.NoError(t, err)

	fmt.Println("---")

	_ = sender.SyncSharedNotes()
	_ = receiver.SyncSharedNotes()

	senderBalance1 := sender.GetBalance()
	recieverBalance1 := receiver.GetBalance()
	require.EqualValues(t, new(uint256.Int).Sub(senderBalance0, new(uint256.Int).Add(amt, fee)), senderBalance1)
	require.EqualValues(t, new(uint256.Int).Add(recieverBalance0, amt), recieverBalance1)

	fmt.Println("sender balance  : ", senderBalance0.Dec(), "-->", senderBalance1.Dec())
	fmt.Println("receiver balance: ", recieverBalance0.Dec(), "-->", recieverBalance1.Dec())
}

func Test_NonExistNote(t *testing.T) {
	sender := prover.Wallets[0]
	receiver := prover.Wallets[5]
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	nonExistNote := &types.Note{
		Version: 1,
		PubKey:  sender.PrivateKey.Public(),
		Balance: uint256.NewInt(1_000_000),
		Salt:    types.RandBytes(32),
	}

	// get merkle proof info for the existing note.
	existNote := sender.GetSharedNote(0).ToNoteOf(sender.PrivateKey.Public())
	rootHash, proofPath, depth, idx, numLeaves, err := verifier.GetNoteCommitmentMerkle(existNote.Commitment())
	require.NoError(t, err)
	fmt.Printf("Merkle Info: numLeaves=%d, idx=%d, depth=%d, proofPath.len=%d\n", numLeaves, idx, depth, len(proofPath))

	// expected error: nonExistNote.Commitment() is not in the proofPath
	_, err = prover.CreateZKTx(
		sender.PrivateKey,
		receiver.Address, amt, fee,
		nonExistNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	require.Error(t, err)

	// fake the proofPath to have the nonExistNote.Commitment()
	proofPath[0] = nonExistNote.Commitment()

	// expected error: rootHash is not same
	_, err = prover.CreateZKTx(
		sender.PrivateKey,
		receiver.Address, amt, fee,
		nonExistNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	require.Error(t, err)
}

func Test_WrongNewSharedNote(t *testing.T) {
	sender := prover.Wallets[1]
	receiver := prover.Wallets[6]
	amt, fee := uint256.NewInt(10), uint256.NewInt(0)

	senderBalance0 := sender.GetBalance()
	recieverBalance0 := receiver.GetBalance()

	useSharedNote := sender.GetSharedNote(0)
	useNote := useSharedNote.ToNoteOf(sender.PrivateKey.Public())
	useNoteCommitment := useNote.Commitment()

	// get merkle proof info.
	rootHash, proofPath, depth, idx, _, err := verifier.GetNoteCommitmentMerkle(useNoteCommitment)
	require.NoError(t, err)
	//fmt.Printf("Merkle Info: numLeaves=%d, idx=%d, depth=%d, proofPath.len=%d\n", numLeaves, idx, depth, len(proofPath))

	// generate the ZKTx including zk-proof
	zkTx, err := prover.CreateZKTx(
		sender.PrivateKey,
		receiver.Address, amt, fee,
		useNote,
		rootHash, proofPath, depth, idx,
		prKey, css,
	)
	require.NoError(t, err)

	//
	// modify the zkTx.NewSecretNote
	fakedNewSharedNote := &types.SharedNote{
		Version: 1,
		Balance: new(uint256.Int).Add(amt, amt),
		Salt:    types.RandBytes(32),
		Memo:    nil,
	}
	zkTx.NewSecretNotes[0], err = types.EncryptSharedNote(fakedNewSharedNote, nil, receiver.PrivateKey.Public())
	require.NoError(t, err)

	// send the ZKTx to the verifier
	err = verifier.VerifyZKTx(zkTx)
	require.NoError(t, err)

	fmt.Println("---")

	_ = sender.SyncSharedNotes()
	_ = receiver.SyncSharedNotes()

	senderBalance1 := sender.GetBalance()
	recieverBalance1 := receiver.GetBalance()
	require.EqualValues(t, new(uint256.Int).Sub(senderBalance0, new(uint256.Int).Add(amt, fee)), senderBalance1)
	require.EqualValues(t, recieverBalance0, recieverBalance1)

	fmt.Println("sender balance  : ", senderBalance0.Dec(), "-->", senderBalance1.Dec())
	fmt.Println("receiver balance: ", recieverBalance0.Dec(), "-->", recieverBalance1.Dec())
}
