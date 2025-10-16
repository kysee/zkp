package vote

import (
	"bytes"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-vote/common"
)

var (
	votePapers               map[[32]byte]*VotePaper
	merkleVotePapers         *merkletree.Tree
	MerkleVotePapersBytes    []byte
	MerkleVotePapersRootHash []byte
)

type VotePaper struct {
	VotePaperID [32]byte
	Choice      []byte
}

func NewVotePaper(id, choice []byte) *VotePaper {
	return &VotePaper{
		VotePaperID: toVotePaperID(id),
		Choice:      choice,
	}
}

func toVotePaperID(id []byte) [32]byte {
	var vpid [32]byte
	copy(vpid[:], id[:32])
	return vpid
}

func FindVotePaper(id []byte) *VotePaper {
	vp := votePapers[toVotePaperID(id)]
	return vp
}

func InitializeVotePapers(n int) {
	votePapers = make(map[[32]byte]*VotePaper)
	merkleVotePapers = merkletree.New(utils.MiMCHasher())
}

func DoVote(proof groth16.Proof, votePaperId, choice []byte) error {
	tmpAssignment := VoteCircuit{
		CitizenMerkleRoot: common.MerkleCitizensRootHash,
		VotePaperID:       votePaperId,
		Choice:            choice,
	}
	pubWtn, err := frontend.NewWitness(&tmpAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	err = groth16.Verify(proof, VerifyingKey, pubWtn)
	if err != nil {
		return err
	}
	addVotePaper(votePaperId, choice)
	return nil
}

func addVotePaper(id, result []byte) {
	votePapers[toVotePaperID(id)] = NewVotePaper(id, result)

	merkleVotePapers.Push(id)
	MerkleVotePapersBytes = append(MerkleVotePapersBytes, id...)
	MerkleVotePapersRootHash = merkleVotePapers.Root()
}

func GetVotePaperCnt() int {
	return len(votePapers)
}

func GetChoiceCnt(choice []byte) int {
	cnt := 0
	for _, v := range votePapers {
		if v.Choice != nil && bytes.Equal(v.Choice, choice) {
			cnt++
		}
	}
	return cnt
}

func (vp *VotePaper) GetChoice() []byte {
	var res []byte
	res = append(res, vp.Choice...)
	return res
}
