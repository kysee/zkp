package vote

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	ecc_tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	std_tedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/kysee/zkp/utils"
)

var (
	R1CS         constraint.ConstraintSystem
	ProvingKey   groth16.ProvingKey
	VerifyingKey groth16.VerifyingKey
	E128         = new(big.Int).Lsh(big.NewInt(1), 128)
)

type VoteCircuit struct {
	curveID     ecc_tedwards.ID
	M           merkle.MerkleProof
	LeafIdx     frontend.Variable
	S0          frontend.Variable
	S1          frontend.Variable
	DIDPubKey   eddsa.PublicKey
	VotePaperID frontend.Variable `gnark:",public"`
	Choice      frontend.Variable `gnark:",public"`
	ChoiceSig   eddsa.Signature
}

func (cc *VoteCircuit) Define(api frontend.API) error {
	hFunc, _ := mimc.NewMiMC(api)

	//
	// 0. a prover should be a citizen
	hFunc.Write(cc.DIDPubKey.A.X, cc.DIDPubKey.A.Y)
	h0 := hFunc.Sum()

	api.AssertIsEqual(h0, cc.M.Path[0])

	//api.Println("h0        ", h0)
	//api.Println("M.Path[0] ", cc.M.Path[0])
	//api.Println("M.RootHash", cc.M.RootHash)
	//api.Println("LeafIdx", cc.LeafIdx)

	hFunc.Reset()
	cc.M.VerifyProof(api, &hFunc, cc.LeafIdx)

	//
	// 1. DIDPubKey should be driven from PrvKeyScalar : check that a prover owns a private key of a DIDPubKey
	curve, err := std_tedwards.NewEdCurve(api, cc.curveID)
	if err != nil {
		return err
	}

	//
	// compute a public key from a privatek key's scalar.
	// 	when private_key_scalar = s1 * 2**128 + s2,
	//	c1 = s1 * base
	// 	c2 = s2 * base
	// 	public key = c1 * 2**128 + c2

	_ = api.ToBinary(cc.S0, 128)
	_ = api.ToBinary(cc.S1, 128)

	// compute c1 = s1 * base
	base := std_tedwards.Point{}
	base.X = curve.Params().Base[0]
	base.Y = curve.Params().Base[1]

	//api.Println("DIDPubKey.A.X     ", cc.DIDPubKey.A.X)
	//api.Println("DIDPubKey.A.Y     ", cc.DIDPubKey.A.Y)

	c1 := curve.ScalarMul(base, cc.S0)
	// compute c128 = c1 * 2**128
	c128 := curve.ScalarMul(c1, E128.Bytes())
	// compute c2 = s2 * base
	c2 := curve.ScalarMul(base, cc.S1)

	// compute pubkey = c128 + c2
	computedPub := curve.Add(c128, c2)

	//api.Println("   computed.X     ", computedPub.X)
	//api.Println("   computed.Y     ", computedPub.Y)

	curve.AssertIsOnCurve(computedPub)
	api.AssertIsEqual(cc.DIDPubKey.A.X, computedPub.X)
	api.AssertIsEqual(cc.DIDPubKey.A.Y, computedPub.Y)

	//
	// 2. check VotePaperID == Hash(PrvKeyScalar, DIDPubKey.A.X, DIDPubKey.A.Y)
	hFunc.Reset()
	hFunc.Write(cc.S0, cc.S1, cc.DIDPubKey.A.X, cc.DIDPubKey.A.Y)
	h1 := hFunc.Sum()

	//cs.Println("h1         ", h1)
	//cs.Println("VotePaperID", cc.VotePaperID)

	api.AssertIsEqual(cc.VotePaperID, h1)

	hFunc.Reset()
	err = eddsa.Verify(curve, cc.ChoiceSig, cc.Choice, cc.DIDPubKey, &hFunc)
	if err != nil {
		return err
	}

	return nil
}

func (cc *VoteCircuit) SetCurveId(curveID ecc_tedwards.ID) {
	cc.curveID = curveID
}

func (cc *VoteCircuit) GetCurveId() ecc_tedwards.ID {
	return cc.curveID
}

func (cc *VoteCircuit) AssignPubKey(pubKey signature.PublicKey) {
	cc.DIDPubKey.Assign(cc.curveID, pubKey.Bytes())
}

func (cc *VoteCircuit) AssignSig(sigBytes []byte) {
	cc.ChoiceSig.Assign(cc.curveID, sigBytes)
}

func CompileCircuit(depth int) error {
	var err error
	var cc VoteCircuit

	cc.curveID = utils.CURVEID
	cc.M.Path = make([]frontend.Variable, depth+1)
	if R1CS, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cc); err != nil {
		return err
	}
	if ProvingKey, VerifyingKey, err = groth16.Setup(R1CS); err != nil {
		return err
	}
	return nil
}
