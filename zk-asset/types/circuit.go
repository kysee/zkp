package types

import (
	ecc_tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type ZKCircuit struct {
	curveID ecc_tedwards.ID

	FromPrvScalar frontend.Variable
	FromPub       eddsa.PublicKey
	Balance       frontend.Variable
	Salt0         frontend.Variable

	Amount frontend.Variable
	Fee    frontend.Variable
	ToPub  eddsa.PublicKey
	Salt1  frontend.Variable

	noteSpent   frontend.Variable
	noteReceipt frontend.Variable `gnark:",public"`
	noteChanges frontend.Variable `gnark:",public"`
	Nullifiers  frontend.Variable `gnark:",public"`
}

func (cc *ZKCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, cc.curveID)
	if err != nil {
		return err
	}
	hasher, err := poseidon2.NewMerkleDamgardHasher(api)
	if err != nil {
		return err
	}

	// ToPub 이 유효한 점인지 확인
	curve.AssertIsOnCurve(cc.ToPub.A)

	needAmt := api.Add(cc.Amount, cc.Fee)
	api.AssertIsLessOrEqual(needAmt, cc.Balance)

	// verify spent note
	hasher.Write(cc.FromPub.A.X, cc.FromPub.A.Y, cc.Balance, cc.Salt0)
	api.AssertIsEqual(cc.noteSpent, hasher.Sum())

	// verify new note
	hasher.Reset()
	hasher.Write(cc.ToPub.A.X, cc.ToPub.A.Y, cc.Amount, cc.Salt1)
	api.AssertIsEqual(cc.noteReceipt, hasher.Sum())

	// verify changes note
	changes := api.Sub(cc.Balance, needAmt)

	// changes가 0인지 확인
	isZero := api.IsZero(changes)

	// changes > 0인 경우 거스름돈 노트 해시 계산
	hasher.Reset()
	hasher.Write(cc.FromPub.A.X, cc.FromPub.A.Y, changes, cc.Salt0)
	changesNote := hasher.Sum()

	// changes가 0이면 noteChanges는 0이어야 하고,
	// changes가 0이 아니면 noteChanges는 changesNote와 같아야 함
	expectedChanges := api.Select(isZero, 0, changesNote)
	api.AssertIsEqual(cc.noteChanges, expectedChanges)

	return nil
}
