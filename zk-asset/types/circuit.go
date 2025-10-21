package types

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	ecc_tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	std_tedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash"
	std_mimc "github.com/consensys/gnark/std/hash/mimc"
	std_eddsa "github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test/unsafekzg"
)

var (
	E128 = new(big.Int).Lsh(big.NewInt(1), 128)
)

type ZKCircuit struct {
	curveID ecc_tedwards.ID

	FromPrv0 frontend.Variable
	FromPrv1 frontend.Variable

	NoteVer frontend.Variable

	// used note
	FromPub        std_eddsa.PublicKey
	Balance        frontend.Variable
	Salt0          frontend.Variable
	NoteCommitment frontend.Variable
	NoteIdx        frontend.Variable
	NoteMerklePath []frontend.Variable
	NoteMerkleRoot frontend.Variable `gnark:",public"`
	Nullifier      frontend.Variable `gnark:",public"`

	// new notes (new note and change note)
	Amount frontend.Variable
	Fee    frontend.Variable
	ToPub  std_eddsa.PublicKey
	Salt1  frontend.Variable

	NewNoteCommitment    frontend.Variable `gnark:",public"`
	ChangeNoteCommitment frontend.Variable `gnark:",public"`
}

func (cc *ZKCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, cc.curveID)
	if err != nil {
		return err
	}

	hasher, err := std_mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	cc.verifyKeys(api, curve)
	cc.verifyNoteCommitment(api, &hasher)
	cc.verifyNewNoteCommitment(api, &hasher)
	cc.verifyChangeNoteCommitment(api, &hasher)
	return nil
}

func (cc *ZKCircuit) verifyKeys(api frontend.API, curve std_tedwards.Curve) {
	//
	//	verify PrvKey Ownership
	//
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

	// ToPub 이 유효한 점인지 확인
	curve.AssertIsOnCurve(cc.ToPub.A)
}

func (cc *ZKCircuit) verifyNoteCommitment(api frontend.API, hasher hash.FieldHasher) {
	//
	// verify NoteCommitment
	// Merkle proof 검증 - numLeaves를 고려한 custom verification
	cc.verifyMerkleProof(api, hasher)

	// check balance
	needAmt := api.Add(cc.Amount, cc.Fee)
	api.AssertIsLessOrEqual(needAmt, cc.Balance)

	hasher.Reset()
	// 각 필드를 개별적으로 Write (Go 코드와 동일하게)
	hasher.Write(
		cc.NoteVer,
		cc.FromPub.A.X,
		cc.FromPub.A.Y,
		cc.Balance,
		cc.Salt0,
	)
	computedCommitment := hasher.Sum()

	api.Println("Expected NoteCommitment:", cc.NoteCommitment)
	api.Println("Computed NoteCommitment:", computedCommitment)

	api.AssertIsEqual(cc.NoteCommitment, computedCommitment)

	//
	// verify Nullifier
	// Step 1: Nullifier key 파생
	// nk = Hash(private_key, "nullifier_key")

	hasher.Reset()
	// 각 필드를 개별적으로 Write
	hasher.Write(cc.FromPrv0, cc.FromPrv1)
	// Domain separator (선택적으로 추가)
	nk := hasher.Sum()

	// Step 2: Nullifier 계산
	// nf = Hash(nk, note_commitment)
	hasher.Reset()
	hasher.Write(nk, cc.NoteCommitment) // note commitment
	computedNullifier := hasher.Sum()

	// Step 3: ⭐ 계산된 nullifier가 public input과 일치하는지 검증 ⭐
	// 이것이 핵심! Circuit이 올바른 nullifier를 계산했음을 증명
	api.Println("Expected Nullifier:", cc.Nullifier)
	api.Println("Computed Nullifier:", computedNullifier)

	api.AssertIsEqual(cc.Nullifier, computedNullifier)
}

func (cc *ZKCircuit) verifyNewNoteCommitment(api frontend.API, hasher hash.FieldHasher) {

	//
	// verify NewNoteCommitment
	//
	hasher.Reset()
	hasher.Write(cc.NoteVer, cc.ToPub.A.X, cc.ToPub.A.Y, cc.Amount, cc.Salt1)
	calculatedCommitment := hasher.Sum()

	api.Println("Expected NewNoteCommitment:", cc.NewNoteCommitment)
	api.Println("Computed NewNoteCommitment:", calculatedCommitment)

	api.AssertIsEqual(cc.NewNoteCommitment, calculatedCommitment)
}

// verifyMerkleProof는 gnark std library의 VerifyProof를 사용
func (cc *ZKCircuit) verifyMerkleProof(api frontend.API, hasher hash.FieldHasher) {
	api.AssertIsEqual(cc.NoteMerklePath[0], cc.NoteCommitment)
	mp := merkle.MerkleProof{
		RootHash: cc.NoteMerkleRoot,
		Path:     cc.NoteMerklePath,
	}
	depth := len(mp.Path) - 1
	sum := _leafSum(hasher, mp.Path[0])

	// The binary decomposition is the bitwise negation of the order of hashes ->
	// If the path in the plain go code is 					0 1 1 0 1 0
	// The binary decomposition of the leaf index will be 	1 0 0 1 0 1 (little endian)
	binLeaf := api.ToBinary(cc.NoteIdx, depth)

	for i := 0; i < 5; i++ {
		api.Println("   Path[", i, "]:", mp.Path[i])
	}
	for i := 1; i < len(mp.Path); i++ { // the size of the loop is fixed -> one circuit per size
		d1 := api.Select(binLeaf[i-1], mp.Path[i], sum)
		d2 := api.Select(binLeaf[i-1], sum, mp.Path[i])
		newSum := _nodeSum(hasher, d1, d2)
		sum = api.Select(api.IsZero(mp.Path[i]), sum, newSum)
	}

	api.Println("Expected RootHash:", cc.NoteMerkleRoot)
	api.Println("Computed RootHash:", sum)

	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(sum, mp.RootHash)
}

// leafSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func _leafSum(h hash.FieldHasher, data frontend.Variable) frontend.Variable {

	h.Reset()
	h.Write(data)
	res := h.Sum()

	return res
}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func _nodeSum(h hash.FieldHasher, a, b frontend.Variable) frontend.Variable {

	h.Reset()
	h.Write(a, b)
	res := h.Sum()

	return res
}

func (cc *ZKCircuit) verifyChangeNoteCommitment(api frontend.API, hasher hash.FieldHasher) {
	//
	// verify ChangeNoteCommitment
	//
	change := api.Sub(cc.Balance, cc.Amount, cc.Fee)

	// change가 0인지 확인
	isZero := api.IsZero(change)

	// change > 0인 경우 거스름돈 노트 해시 계산
	hasher.Reset()
	hasher.Write(cc.NoteVer, cc.FromPub.A.X, cc.FromPub.A.Y, change, cc.Salt0)
	changeNoteC := hasher.Sum()

	// change가 0 이면 `calculatedCommitment`는 무조건 `0`,
	// change가 0 아니면 `calculatedCommitment`는 올바른 change 를 포함하여 해싱된 값.
	calculatedCommitment := api.Select(isZero, 0, changeNoteC)

	api.Println("Expected ChangeNoteCommitment:", cc.ChangeNoteCommitment)
	api.Println("Computed ChangeNoteCommitment:", calculatedCommitment)

	api.AssertIsEqual(cc.ChangeNoteCommitment, calculatedCommitment)
}

func (cc *ZKCircuit) SetCurveId(curveID ecc_tedwards.ID) {
	cc.curveID = curveID
}

func (cc *ZKCircuit) GetCurveId() ecc_tedwards.ID {
	return cc.curveID
}

func (cc *ZKCircuit) AssignPrivKey(sk0, sk1 []byte) {
	cc.FromPrv0, cc.FromPrv1 = sk0, sk1
}

func (cc *ZKCircuit) AssignTransfer(n *Note) {
	cc.NoteVer = n.Version
	cc.FromPub.Assign(cc.curveID, n.PubKey.Bytes())
	cc.Balance = n.Balance
	cc.Salt0 = n.Salt
	cc.NoteCommitment = n.Commitment()
}

func CompileCircuit(depth int) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey) {
	var err error
	var cc ZKCircuit

	cc.curveID = ecc_tedwards.BN254
	cc.NoteMerklePath = make([]frontend.Variable, depth+1)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &cc)
	if err != nil {
		panic(err)
	}

	// todo: Use safe SRS generation
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	provingKey, verifyingKey, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	return ccs, provingKey, verifyingKey
}
