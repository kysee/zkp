package gov

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-vote/common"
	"github.com/kysee/zkp/zk-vote/vote"
	"github.com/rs/zerolog"
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
	didPrvKey, _ := eddsa.GenerateKey(rand.Reader)

	return &Citizen{
		Name:      name,
		SN:        sn,
		DIDPrvKey: didPrvKey,
		DIDPubKey: didPrvKey.Public(),
	}
}

func (c *Citizen) HashDIDPubKey() []byte {
	var p twistededwards.PointAffine
	_, _ = p.SetBytes(c.DIDPubKey.Bytes())
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
	tmpPrvKey, _ := eddsa.GenerateKey(rand.Reader)
	c.TmpVotePrvKey = tmpPrvKey
	c.TmpVotePubKey = tmpPrvKey.Public()

	s1, s2 := c.GetPrvScalar()
	x := c.DIDPubKey.(*eddsa.PublicKey).A.X.Bytes()
	y := c.DIDPubKey.(*eddsa.PublicKey).A.Y.Bytes()

	c.VotePaperID = utils.ComputeHash(s1[:], s2[:], x[:], y[:])
}

var gnarkLogger = zerolog.New(os.Stdout).Level(zerolog.DebugLevel).With().Timestamp().Logger()

func (c *Citizen) VoteProof(choice []byte) (groth16.Proof, error) {
	if c.VotePaperID == nil {
		return nil, errors.New("VotePaperID should not be nil")
	}

	cidx := c.GetIndex()
	if cidx < 0 {
		return nil, errors.New("not found index in merkle")
	}
	citizenIdx := uint64(cidx)

	rootHash, proofPath, numLeaves, err := merkletree.BuildReaderProof(
		bytes.NewBuffer(MerkleCitizensBytes),
		utils.DefaultHasher(),
		utils.DefaultHasher().Size(),
		citizenIdx,
	)
	if err != nil {
		return nil, err
	}

	// verify the proof in plain go
	verified := merkletree.VerifyProof(utils.DefaultHasher(), rootHash, proofPath, citizenIdx, numLeaves)
	if !verified {
		return nil, errors.New("the merkle proof in plain go should pass")
	}

	var assignment vote.VoteCircuit
	assignment.SetCurveId(utils.CURVEID)
	assignment.LeafIdx = citizenIdx
	assignment.CitizenMerkleRoot = common.MerkleCitizensRootHash
	assignment.M.RootHash = rootHash
	assignment.M.Path = make([]frontend.Variable, len(proofPath))
	for i := 0; i < len(proofPath); i++ {
		assignment.M.Path[i] = proofPath[i]
	}

	// private scalar & vote paper id
	s0, s1 := c.GetPrvScalar()
	assignment.S0, assignment.S1 = s0, s1
	assignment.AssignPubKey(c.DIDPubKey)
	assignment.VotePaperID = c.VotePaperID
	assignment.Choice = choice

	sig, err := c.DIDPrvKey.Sign(choice, utils.DefaultHasher())
	if err != nil {
		return nil, err
	}
	assignment.AssignSig(sig)

	wtn, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	proof, err := groth16.Prove(
		vote.R1CS,
		vote.ProvingKey,
		wtn,
		backend.WithSolverOptions(
			solver.WithLogger(gnarkLogger),
		),
	)
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
