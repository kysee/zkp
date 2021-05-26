package gov

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-vote/vote"
	"math/big"
)

type Citizen struct {
	Name string
	SN   string

	DIDPrvKey signature.Signer
	DIDPubKey signature.PublicKey

	VotePaperID   []byte
	TmpVotePrvKey signature.Signer
	TmpVotePubKey signature.PublicKey
}

func NewCitizen(name, sn string) *Citizen {
	didPrvKey, _ := eddsa.GenerateKeyInterfaces(rand.Reader)

	return &Citizen{
		Name:      name,
		SN:        sn,
		DIDPrvKey: didPrvKey,
		DIDPubKey: didPrvKey.Public(),
	}
}

func (c *Citizen) HashDIDPubKey() []byte {
	var p twistededwards.PointAffine
	p.SetBytes(c.DIDPubKey.Bytes())
	x := p.X.Bytes()
	y := p.Y.Bytes()

	return utils.ComputeHash(x[:], y[:])
}

func (c *Citizen) GetIndex() int {
	return GetCitizenIdx(c)
}

func (c *Citizen) String() string {
	return fmt.Sprintf("Name:%s, SN:%s, did:%x, tmp:%x, VotePaperID:%x", c.Name, c.SN, c.DIDPubKey.Bytes(), c.TmpVotePubKey.Bytes(), c.VotePaperID)
}

func (c *Citizen) GetPrvScalar() ([]byte, []byte) {
	s := c.DIDPrvKey.Bytes()[32:64]
	return s[:16], s[16:32]
}

func (c *Citizen) MakeVotePaperID() {
	tmpPrvKey, _ := eddsa.GenerateKeyInterfaces(rand.Reader)
	c.TmpVotePrvKey = tmpPrvKey
	c.TmpVotePubKey = tmpPrvKey.Public()

	s1, s2 := c.GetPrvScalar()
	x := c.DIDPubKey.(*eddsa.PublicKey).A.X.Bytes()
	y := c.DIDPubKey.(*eddsa.PublicKey).A.Y.Bytes()

	c.VotePaperID = utils.ComputeHash(s1[:], s2[:], x[:], y[:])
}

func (c *Citizen) VoteProof(choice []byte, force ...bool) (groth16.Proof, error) {
	if c.VotePaperID == nil {
		return nil, errors.New("not found VotePaperID")
	}

	cidx := c.GetIndex()
	if cidx < 0 {
		return nil, errors.New("not found index in merkle")
	}
	citizenIdx := uint64(cidx)

	rootHash, proofSet, numLeaves, err := merkletree.BuildReaderProof(
		bytes.NewBuffer(MerkleCitizensBytes),
		utils.HASHER, utils.HASHER.Size(), citizenIdx)
	if err != nil {
		return nil, err
	}

	helperSet := merkle.GenerateProofHelper(proofSet, citizenIdx, numLeaves)

	var wtn vote.VoteCircuit
	wtn.CitizensRootHash.Assign(rootHash)
	wtn.Path = make([]frontend.Variable, len(proofSet))
	for i := 0; i < len(proofSet); i++ {
		wtn.Path[i].Assign(proofSet[i])
	}
	wtn.Helper = make([]frontend.Variable, len(helperSet))
	for i := 0; i < len(helperSet); i++ {
		wtn.Helper[i].Assign(helperSet[i])
	}

	// private scalar & vote paper id
	e128 := new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil)
	wtn.E128.Assign(e128.Bytes())
	s1, s2 := c.GetPrvScalar()
	wtn.PrvKeyS1.Assign(s1[:])
	wtn.PrvKeyS2.Assign(s2[:])
	wtn.AssignPubKey(c.DIDPubKey)
	wtn.VotePaperID.Assign(c.VotePaperID)
	wtn.Choice.Assign(choice)

	sig, err := c.DIDPrvKey.Sign(choice, utils.HASHER)
	if err != nil {
		return nil, err
	}
	wtn.AssignSig(sig)

	_force := false
	if len(force) > 0 {
		_force = force[0]
	}

	proof, err := groth16.Prove(vote.R1CS, vote.ProvingKey, &wtn, _force)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

//func (c *Citizen) ProofVoting(selection string) (groth16.Proof, error) {
//	var wtn voting.VotingCircuit
//	wtn.H0.Assign(c.Hash0())
//	wtn.H1.Assign(c.Hash1())
//	wtn.VotePaperID.Assign( c.VotePaperID )
//	wtn.Selection.Assign([]byte(selection))
//	wtn.RetHash.Assign(utils.ComputeHash(c.VotePaperID, []byte(selection)))
//
//	return  groth16.Prove(voting.R1CS, voting.ProvingKey, &wtn)
//}
