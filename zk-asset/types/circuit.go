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

	Nullifiers   frontend.Variable `gnark:",public"`
	noteCommit00 frontend.Variable `gnark:",public"`
	noteCommit01 frontend.Variable `gnark:",public"`
	noteCommit10 frontend.Variable `gnark:",public"`
}

func (cc *ZKCircuit) Define(api frontend.API) error {
	need := api.Add(cc.Amount, cc.Fee)
	api.AssertIsLessOrEqual(need, cc.Balance)

	hasher, err := poseidon2.NewMerkleDamgardHasher(api)
	if err != nil {
		return err
	}

	// verify old balance
	hasher.Write(cc.FromPub, cc.Balance, cc.Salt0)
	api.AssertIsEqual(cc.noteCommit00, hasher.Sum())

	hasher.Reset()

	// verify other's balance
	hasher.Write(cc.ToPub, cc.Amount, cc.Salt1)
	api.AssertIsEqual(cc.noteCommit10, hasher.Sum())

	curve, err := twistededwards.NewEdCurve(api, cc.curveID)
	if err != nil {
		return err
	}

	toPubPt := cc.ToPub.A
	// toPubPt가 유효한 점인지 확인
	curve.AssertIsOnCurve(toPubPt)

	// ECDH: shared_secret = my_private_scalar * their_public_key
	sharedSecret := curve.ScalarMul(toPubPt, cc.FromPrvScalar)

	// 공유키를 해시하여 암호화 키 생성
	hasher.Reset()
	hasher.Write(sharedSecret)
	encKey := hasher.Sum()

	return nil
}

func GenerateSharedSecret(myPrivateKey *tedwards.PrivateKey, theirPublicKey *tedwards.PublicKey) tedwards.Point {
	// 공유키 = 나의 private key scalar * 상대방의 public key point
	var sharedSecret tedwards.Point
	sharedSecret.ScalarMultiplication(&theirPublicKey.A, myPrivateKey.Scalar)

	return sharedSecret
}
