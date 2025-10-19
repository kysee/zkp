package zk_asset

import (
	"fmt"
	"testing"

	"github.com/holiman/uint256"
	"github.com/kysee/zkp/zk-asset/node"
	"github.com/kysee/zkp/zk-asset/types"
	"github.com/stretchr/testify/require"
)

var (
	wallets []*Wallet
)

func init() {
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
	css, prKey, _ := types.CompileCircuit(node.GetNoteCommitmentMerkleDepth())

	sender := wallets[0]
	receiver := wallets[5]

	zkTx, err := sender.TransferProof(receiver.Address, uint256.NewInt(10), uint256.NewInt(0), prKey, css)
	require.NoError(t, err)
	fmt.Printf("proof      : (%4dB) %x\n", len(zkTx.ProofBytes), zkTx.ProofBytes)
	fmt.Printf("merkle root: (%4dB) %x\n", len(zkTx.MerkleRoot), zkTx.MerkleRoot)
	fmt.Printf("nullifier  : (%4dB) %x\n", len(zkTx.Nullifier), zkTx.Nullifier)
	fmt.Printf("newNote    : (%4dB) %x\n", len(zkTx.NewNoteCommitment), zkTx.NewNoteCommitment)
	fmt.Printf("changeNote : (%4dB) %x\n", len(zkTx.ChangeNoteCommitment), zkTx.ChangeNoteCommitment)

	require.NoError(t, node.SendZKTransaction(zkTx))

	newRoot := node.GetNoteCommitmentsRoot()
	fmt.Printf("---\nnew merkle : (%4dB) %x\n", len(newRoot), newRoot)

}
