package vote

import (
	"github.com/consensys/gnark-crypto/ecc"
	twistededwards_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

var (
	R1CS         frontend.CompiledConstraintSystem
	ProvingKey   groth16.ProvingKey
	VerifyingKey groth16.VerifyingKey
)

type VoteCircuit struct {
	CitizensRootHash frontend.Variable `gnark:",public"`
	Path, Helper     []frontend.Variable

	E128        frontend.Variable
	PrvKeyS1    frontend.Variable
	PrvKeyS2    frontend.Variable
	DIDPubKey   eddsa.PublicKey
	VotePaperID frontend.Variable `gnark:",public"`
	Choice      frontend.Variable `gnark:",public"`
	ChoiceSig   eddsa.Signature
}

func (cc *VoteCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	hFunc, _ := mimc.NewMiMC("seed", curveID)

	//
	// 0. a prover should be a citizen
	h0 := hFunc.Hash(cs, cc.DIDPubKey.A.X, cc.DIDPubKey.A.Y)
	//cs.Println("h0     ", h0)
	//cs.Println("Path[0]", cc.Path[0])
	cs.AssertIsEqual(cc.Path[0], h0)
	merkle.VerifyProof(cs, hFunc, cc.CitizensRootHash, cc.Path[:], cc.Helper[:])

	//
	// 1. DIDPubKey should be driven from PrvKeyScalar : check that a prover owns a private key of a DIDPubKey
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	cc.DIDPubKey.Curve = params

	computedPub0 := twistededwards.Point{}
	computedPub0.ScalarMulFixedBase(cs, cc.DIDPubKey.Curve.BaseX, cc.DIDPubKey.Curve.BaseY, cc.PrvKeyS1, cc.DIDPubKey.Curve)

	computedPub1 := twistededwards.Point{}
	computedPub1.ScalarMulNonFixedBase(cs, &computedPub0, cc.E128, cc.DIDPubKey.Curve)

	computedPub2 := twistededwards.Point{}
	computedPub2.ScalarMulFixedBase(cs, cc.DIDPubKey.Curve.BaseX, cc.DIDPubKey.Curve.BaseY, cc.PrvKeyS2, cc.DIDPubKey.Curve)

	computedPub := twistededwards.Point{}
	computedPub.AddGeneric(cs, &computedPub1, &computedPub2, cc.DIDPubKey.Curve)
	computedPub.MustBeOnCurve(cs, cc.DIDPubKey.Curve)

	//cs.Println("DIDPubKey.A.X     ", cc.DIDPubKey.A.X)
	//cs.Println("   computed.X     ", computedPub.X)
	//cs.Println("DIDPubKey.A.Y     ", cc.DIDPubKey.A.Y)
	//cs.Println("   computed.Y     ", computedPub.Y)

	cs.AssertIsEqual(cc.DIDPubKey.A.X, computedPub.X)
	cs.AssertIsEqual(cc.DIDPubKey.A.Y, computedPub.Y)

	//
	// 2. check VotePaperID == Hash(PrvKeyScalar, DIDPubKey.A.X, DIDPubKey.A.Y)
	h1 := hFunc.Hash(cs, cc.PrvKeyS1, cc.PrvKeyS2, cc.DIDPubKey.A.X, cc.DIDPubKey.A.Y)

	//cs.Println("h1         ", h1)
	//cs.Println("VotePaperID", cc.VotePaperID)

	cs.AssertIsEqual(cc.VotePaperID, h1)

	err = eddsa.Verify(cs, cc.ChoiceSig, cc.Choice, cc.DIDPubKey)
	if err != nil {
		return err
	}

	return nil
}

func (cc *VoteCircuit) AssignPubKey(pubKey signature.PublicKey) {
	var p twistededwards_bn254.PointAffine
	p.SetBytes(pubKey.Bytes()[:32])
	x := p.X.Bytes()
	y := p.Y.Bytes()
	cc.DIDPubKey.A.X.Assign(x[:])
	cc.DIDPubKey.A.Y.Assign(y[:])
}

func (cc *VoteCircuit) AssignSig(sigBytes []byte) {
	var p twistededwards_bn254.PointAffine
	p.SetBytes(sigBytes[:32])
	x := p.X.Bytes()
	y := p.Y.Bytes()
	cc.ChoiceSig.R.X.Assign(x[:])
	cc.ChoiceSig.R.Y.Assign(y[:])

	// The S part of the signature is a 32 bytes scalar stored in signature[32:64].
	// As decribed earlier, we split is in S1, S2 such that S = 2^128*S1+S2 to prevent
	// overflowing the underlying representation in the cc.
	cc.ChoiceSig.S1.Assign(sigBytes[32:48])
	cc.ChoiceSig.S2.Assign(sigBytes[48:])
}

func CompileCircuit(depth int) error {
	var err error
	var cc VoteCircuit

	cc.Path = make([]frontend.Variable, depth)
	cc.Helper = make([]frontend.Variable, depth-1)

	if R1CS, err = frontend.Compile(ecc.BN254, backend.GROTH16, &cc); err != nil {
		return err
	}
	if ProvingKey, VerifyingKey, err = groth16.Setup(R1CS); err != nil {
		return err
	}
	return nil
}
