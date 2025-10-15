package types

import (
	"math/big"

	ecc_tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	std_tedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/signature/eddsa"
)

var (
	E128 = new(big.Int).Lsh(big.NewInt(1), 128)
)

type ZKCircuit struct {
	curveID ecc_tedwards.ID

	FromPrv0 frontend.Variable
	FromPrv1 frontend.Variable
	FromPub  eddsa.PublicKey
	Balance  frontend.Variable
	Salt0    frontend.Variable

	Amount frontend.Variable
	Fee    frontend.Variable
	ToPub  eddsa.PublicKey
	Salt1  frontend.Variable

	noteSpend      frontend.Variable
	noteIdx        frontend.Variable
	noteMerklePath []frontend.Variable
	noteMerkleRoot frontend.Variable `gnark:",public"`

	Nullifiers  frontend.Variable `gnark:",public"`
	noteReceipt frontend.Variable `gnark:",public"`
	noteChanges frontend.Variable `gnark:",public"`
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

	//
	// check the private key ownership
	//
	cc.checkPrvKeyOwnership(api, curve)

	//
	// verify noteSpend
	//

	// check merkle proof
	merkleProof := merkle.MerkleProof{
		RootHash: cc.noteMerkleRoot,
		Path:     cc.noteMerklePath,
	}
	hasher.Reset()
	merkleProof.VerifyProof(api, hasher, cc.noteIdx)

	// check balance
	needAmt := api.Add(cc.Amount, cc.Fee)
	api.AssertIsLessOrEqual(needAmt, cc.Balance)

	hasher.Reset()
	hasher.Write(cc.FromPub.A.X, cc.FromPub.A.Y, cc.Balance, cc.Salt0)
	api.AssertIsEqual(cc.noteSpend, hasher.Sum())

	// ToPub 이 유효한 점인지 확인
	curve.AssertIsOnCurve(cc.ToPub.A)

	//
	// verify noteReceipt
	//
	hasher.Reset()
	hasher.Write(cc.ToPub.A.X, cc.ToPub.A.Y, cc.Amount, cc.Salt1)
	api.AssertIsEqual(cc.noteReceipt, hasher.Sum())

	//
	// verify noteChanges
	//
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

func (cc *ZKCircuit) checkPrvKeyOwnership(api frontend.API, curve std_tedwards.Curve) {
	// Private key scalar = S1 * 2^128 + S0
	// 범위 체크: 각각이 128bit 내에 있는지 확인
	_ = api.ToBinary(cc.FromPrv0, 128)
	_ = api.ToBinary(cc.FromPrv1, 128)

	// 베이스 포인트 설정
	base := std_tedwards.Point{}
	base.X = curve.Params().Base[0]
	base.Y = curve.Params().Base[1]

	// Public Key 계산: PubKey = (S1 * 2^128 + S0) * Base
	// 단계별로:
	// 1) c1 = S0 * Base
	c1 := curve.ScalarMul(base, cc.FromPrv0)

	// 2) c128 = c1 * 2^128 = (S0 * Base) * 2^128 = (S0 * 2^128) * Base
	c128 := curve.ScalarMul(c1, E128.Bytes())

	// 3) c2 = S1 * Base
	c2 := curve.ScalarMul(base, cc.FromPrv1)

	// 4) computedPub = c128 + c2 = (S0 * 2^128 + S1) * Base
	computedPubPt := curve.Add(c128, c2)

	// 타원곡선 위의 점인지 확인
	curve.AssertIsOnCurve(computedPubPt)

	// ✅ 핵심: FromPrvScalar로부터 유도된 공개키가 FromPub과 일치하는지 검증
	api.AssertIsEqual(cc.FromPub.A.X, computedPubPt.X)
	api.AssertIsEqual(cc.FromPub.A.Y, computedPubPt.Y)

}
