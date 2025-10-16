package vote_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/zk-vote/common"
	"github.com/kysee/zkp/zk-vote/gov"
	"github.com/kysee/zkp/zk-vote/vote"
	"github.com/stretchr/testify/require"
)

// 2^0 = 1
// 2^1 = 2
// 2^2 = 4
// 2^3 = 8
// 2^4 = 16
// 2^5 = 32
var (
	merkleCitizensDepth = 4
	citizens            []*gov.Citizen

	choices       = [][]byte{{0x1}, {0x2}, {0x3}}
	choiceResults = []int{0, 0, 0}
)

func init() {
	cnt := 2 << (merkleCitizensDepth - 1)
	citizens = make([]*gov.Citizen, cnt)
	for i := 0; i < cnt; i++ {
		c := gov.NewCitizen(fmt.Sprintf("Name-%d", i), fmt.Sprintf("SN-%d", i))
		gov.RegisterCitizen(c)
		citizens[i] = c
		//fmt.Printf("citizen[%d] Name=%s, SN=%s\n", i, c.Name, c.SN)
	}

	vote.InitializeVotePapers(len(citizens))
	if err := vote.CompileCircuit(merkleCitizensDepth); err != nil {
		panic(err)
	}

	for _, c := range citizens {
		c.MakeVotePaperID()
	}
}

func TestVote(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	for i, c := range citizens {
		r := rand.Intn(len(choices))
		choice := choices[r]

		proof, err := c.VoteProof(choice)
		require.NoError(t, err)

		err = vote.DoVote(proof, c.VotePaperID, choice)
		require.NoError(t, err)
		require.Equal(t, i+1, vote.GetVotePaperCnt())

		choiceResults[r] = choiceResults[r] + 1
	}
	totalChoiceCnt := 0
	for i, cho := range choices {
		require.Equal(t, choiceResults[i], vote.GetChoiceCnt(cho))
		totalChoiceCnt += choiceResults[i]
		//log.Printf("choice=%x, score=%d\n", cho, choiceResults[i])
	}

	vpcnt := vote.GetVotePaperCnt()
	require.Equal(t, totalChoiceCnt, vpcnt)

	fchoice := []byte{0xff}
	fcnt := 0
	for _, c := range citizens {
		r := rand.Intn(len(choices))
		choice := choices[r]

		proof, err := c.VoteProof(choice)
		require.NoError(t, err)

		r = rand.Intn(3)
		if r == 0 {
			// Revoting should be allowed.
			vpaper := vote.FindVotePaper(c.VotePaperID)
			require.NotNil(t, vpaper)
			oriChoice := vpaper.GetChoice()
			choiceResults[int(oriChoice[0])-1] -= 1

			err = vote.DoVote(proof, c.VotePaperID, choice)
			require.NoError(t, err)
			choiceResults[int(choice[0])-1] += 1
		} else {
			// Try with an `fchoice` not used in the proof generation; expected to fail.
			err = vote.DoVote(proof, c.VotePaperID, fchoice)
			require.Error(t, err)
			fcnt++
		}

		require.Equal(t, vpcnt, vote.GetVotePaperCnt())
	}

	totalChoiceCnt = 0
	for i, cho := range choices {
		require.Equal(t, choiceResults[i], vote.GetChoiceCnt(cho))
		totalChoiceCnt += choiceResults[i]
		//log.Printf("choice=%x, score=%d\n", cho, choiceResults[i])
	}

	vpcnt = vote.GetVotePaperCnt()
	require.Equal(t, totalChoiceCnt, vpcnt)
}

func TestDupVote(t *testing.T) {
	backupVotePaperCnt := vote.GetVotePaperCnt()

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 100; i++ {
		c := citizens[rand.Intn(len(citizens))]
		choice := choices[rand.Intn(len(choices))]

		backupVotePaperID := make([]byte, len(c.VotePaperID))
		copy(backupVotePaperID, c.VotePaperID)

		// replace c.VotePaperId with random values
		n, err := rand.Read(c.VotePaperID[:32])
		require.NoError(t, err)
		require.Equal(t, 32, n)
		require.NotEqual(t, backupVotePaperID, c.VotePaperID)

		// `c.VotePaperID` is changed.
		// This is an attempt to cast extra ballots by fabricating them,
		// i.e., an attempt at one person voting multiple times.
		// This means duplicate voting, which must not be allowed.
		proof, err := c.VoteProof(choice)
		require.Error(t, err)
		require.Nil(t, proof)

		// restore c.VotePaperID
		copy(c.VotePaperID, backupVotePaperID)
	}

	for i := 0; i < 100; i++ {
		c := citizens[rand.Intn(len(citizens))]
		choice := choices[rand.Intn(len(choices))]

		proof, err := c.VoteProof(choice)
		require.NoError(t, err)

		otherVotingPaperID := make([]byte, len(c.VotePaperID))
		n, err := rand.Read(otherVotingPaperID)
		require.NoError(t, err)
		require.Equal(t, 32, n)
		require.NotEqual(t, c.VotePaperID, otherVotingPaperID)

		// `otherVotingPaperID` is not used in the proof generation.
		// This means duplicate voting, which must not be allowed.
		err = vote.DoVote(proof, otherVotingPaperID, choice)
		require.Error(t, err)
	}

	require.Equal(t, backupVotePaperCnt, vote.GetVotePaperCnt())
}

func TestFakeVote(t *testing.T) {
	hackerChoice := []byte{0xf}
	backupVotePaperCnt := vote.GetVotePaperCnt()
	backupChoiceResults := make([]int, len(choiceResults))
	copy(backupChoiceResults, choiceResults)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 100; i++ {
		r := rand.Intn(len(citizens))
		hacker := citizens[r]
		victim := citizens[(r+1)%len(citizens)]
		victimIdx := uint64(victim.GetIndex())

		_, proofPath, _, err := merkletree.BuildReaderProof(
			bytes.NewBuffer(gov.MerkleCitizensBytes),
			utils.MiMCHasher(), utils.MiMCHasher().Size(), victimIdx)
		require.NoError(t, err)

		var assignment vote.VoteCircuit
		assignment.SetCurveId(utils.CURVEID)
		assignment.LeafIdx = victimIdx
		assignment.CitizenMerkleRoot = common.MerkleCitizensRootHash
		assignment.CitizenMerklePath = make([]frontend.Variable, len(proofPath))
		for i := 0; i < len(proofPath); i++ {
			assignment.CitizenMerklePath[i] = proofPath[i]
		}

		// private scalar & vote paper id

		// Hacker CAN NOT know the victim's DIDPrvKey.
		// So haskers have no choice but to use their own private keys.
		s1, s2 := hacker.GetPrvScalar()
		assignment.S0 = s1[:]
		assignment.S1 = s2[:]
		assignment.AssignPubKey(victim.DIDPubKey)   // use the victim's DIDPubKey
		assignment.VotePaperID = victim.VotePaperID // use the victim's VotePaperID
		assignment.Choice = hackerChoice

		// Hackers have no choice but sign by using their own DIDPrvKey
		// because hackers CAN NOT know the victim's DIDPrvKey.
		sig, err := hacker.DIDPrvKey.Sign(hackerChoice, utils.MiMCHasher())
		require.NoError(t, err)
		assignment.AssignSig(sig)

		wtn, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		require.NoError(t, err)

		proof, err := groth16.Prove(vote.R1CS, vote.ProvingKey, wtn)
		require.Error(t, err)
		require.Nil(t, proof)
	}

	totalChoiceCnt := 0
	for _, cho := range choices {
		require.Equal(t, backupChoiceResults[cho[0]-1], choiceResults[cho[0]-1])
		require.Equal(t, choiceResults[cho[0]-1], vote.GetChoiceCnt(cho))
		totalChoiceCnt += choiceResults[cho[0]-1]
		//log.Printf("choice=%x, score=%d\n", cho, choiceResults[cho[0]-1])
	}

	require.Equal(t, totalChoiceCnt, backupVotePaperCnt)
	require.Equal(t, backupVotePaperCnt, vote.GetVotePaperCnt())
}
