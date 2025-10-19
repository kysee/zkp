package zk_asset

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/kysee/zkp/zk-asset/node"
	"github.com/kysee/zkp/zk-asset/types"
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

	_ = sender.TransferProof(receiver.Address, uint256.NewInt(10), uint256.NewInt(0), prKey, css)

}
