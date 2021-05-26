package votepaper_test

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/kysee/zkp/utils"
	"github.com/kysee/zkp/vote/gov"
	"github.com/kysee/zkp/vote/votepaper"
	"github.com/stretchr/testify/require"
	"log"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

var (
	merkleCitizensDepth = 5
	citizens            []*gov.Citizen

	choices       = [][]byte{{0x1}, {0x2}, {0x3}}
	choiceResults = []int{0, 0, 0}
)

func init() {
	cnt := 2 << (merkleCitizensDepth - 2)
	citizens = make([]*gov.Citizen, cnt)
	for i := 0; i < cnt; i++ {
		c := gov.NewCitizen(fmt.Sprintf("Name-%d", i), fmt.Sprintf("SN-%d", i))
		gov.RegisterCitizen(c)
		citizens[i] = c
	}

	votepaper.InitializeVotePapers(len(citizens))
	if err := votepaper.CompileCircuit(merkleCitizensDepth); err != nil {
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

		err = votepaper.DoVote(proof, merkleCitizensDepth, gov.MerkleCitizensRootHash, c.VotePaperID, choice)
		require.NoError(t, err)
		require.Equal(t, i+1, votepaper.GetVotePaperCnt())

		choiceResults[r] = choiceResults[r] + 1
	}
	totalChoiceCnt := 0
	for i, cho := range choices {
		require.Equal(t, choiceResults[i], votepaper.GetChoiceCnt(cho))
		totalChoiceCnt += choiceResults[i]
		log.Printf("choice=%x, score=%d\n", cho, choiceResults[i])
	}

	vpcnt := votepaper.GetVotePaperCnt()
	require.Equal(t, totalChoiceCnt, vpcnt)

	fchoice := []byte{0x0f}
	fcnt := 0
	for _, c := range citizens {
		r := rand.Intn(len(choices))
		choice := choices[r]

		proof, err := c.VoteProof(choice)
		require.NoError(t, err)

		r = rand.Intn(3)
		if r == 0 {
			vpaper := votepaper.FindVotePaper(c.VotePaperID)
			require.NotNil(t, vpaper)
			oriChoice := vpaper.GetChoice()
			choiceResults[int(oriChoice[0])-1] -= 1

			err = votepaper.DoVote(proof, merkleCitizensDepth, gov.MerkleCitizensRootHash, c.VotePaperID, choice)
			require.NoError(t, err)
			choiceResults[int(choice[0])-1] += 1
		} else {
			err = votepaper.DoVote(proof, merkleCitizensDepth, gov.MerkleCitizensRootHash, c.VotePaperID, fchoice)
			require.Error(t, err)
			fcnt++
		}

		require.Equal(t, vpcnt, votepaper.GetVotePaperCnt())
	}

	totalChoiceCnt = 0
	for i, cho := range choices {
		require.Equal(t, choiceResults[i], votepaper.GetChoiceCnt(cho))
		totalChoiceCnt += choiceResults[i]
		log.Printf("choice=%x, score=%d\n", cho, choiceResults[i])
	}

	vpcnt = votepaper.GetVotePaperCnt()
	require.Equal(t, totalChoiceCnt, vpcnt)
}

func TestDupVote(t *testing.T) {
	dupChoice := []byte{0xd}
	backupVotePaperCnt := votepaper.GetVotePaperCnt()

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 100; i++ {
		r := rand.Intn(len(citizens))
		c := citizens[r]

		backupVotePaperID := make([]byte, len(c.VotePaperID))
		copy(backupVotePaperID, c.VotePaperID)

		n, err := rand.Read(c.VotePaperID[:32]) // use random VotePaperID
		require.NoError(t, err)
		require.Equal(t, 32, n)
		require.NotEqual(t, backupVotePaperID, c.VotePaperID)

		proof, err := c.VoteProof(dupChoice)
		require.Error(t, err)

		proof, err = c.VoteProof(dupChoice, true)
		require.NoError(t, err)

		err = votepaper.DoVote(proof, merkleCitizensDepth, gov.MerkleCitizensRootHash, c.VotePaperID, dupChoice)
		require.Error(t, err)
	}

	require.Equal(t, backupVotePaperCnt, votepaper.GetVotePaperCnt())
}

func TestFakeVote(t *testing.T) {
	hackerChoice := []byte{0xf}
	backupVotePaperCnt := votepaper.GetVotePaperCnt()
	backupChoiceResults := make([]int, len(choiceResults))
	copy(backupChoiceResults, choiceResults)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 100; i++ {
		r := rand.Intn(len(citizens))
		hacker := citizens[r]
		victim := citizens[(r+1)%len(citizens)]
		victimIdx := uint64(victim.GetIndex())

		rootHash, proofSet, numLeaves, err := merkletree.BuildReaderProof(
			bytes.NewBuffer(gov.MerkleCitizensBytes),
			utils.HASHER, utils.HASHER.Size(), victimIdx)
		require.NoError(t, err)

		helperSet := merkle.GenerateProofHelper(proofSet, victimIdx, numLeaves)

		var wtn votepaper.VoteCircuit
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

		// Hacker CAN NOT know the victim's DIDPrvKey.
		// So haskers have no choice but to use their own private keys.
		s1, s2 := hacker.GetPrvScalar()
		wtn.PrvKeyS1.Assign(s1[:])
		wtn.PrvKeyS2.Assign(s2[:])
		wtn.AssignPubKey(victim.DIDPubKey)         // use the victim's DIDPubKey
		wtn.VotePaperID.Assign(victim.VotePaperID) // use the victim's VotePaperID
		wtn.Choice.Assign(hackerChoice)

		// Hackers have no choice but sign by using their own DIDPrvKey
		// because hackers CAN NOT know the victim's DIDPrvKey.
		sig, err := hacker.DIDPrvKey.Sign(hackerChoice, utils.HASHER)
		require.NoError(t, err)
		wtn.AssignSig(sig)

		proof, err := groth16.Prove(votepaper.R1CS, votepaper.ProvingKey, &wtn)
		require.Error(t, err)

		proof, err = groth16.Prove(votepaper.R1CS, votepaper.ProvingKey, &wtn, true)
		require.NoError(t, err)

		err = votepaper.DoVote(proof, merkleCitizensDepth, gov.MerkleCitizensRootHash, victim.VotePaperID, hackerChoice)
		require.Error(t, err)
	}

	totalChoiceCnt := 0
	for _, cho := range choices {
		require.Equal(t, backupChoiceResults[cho[0]-1], choiceResults[cho[0]-1])
		require.Equal(t, choiceResults[cho[0]-1], votepaper.GetChoiceCnt(cho))
		totalChoiceCnt += choiceResults[cho[0]-1]
		log.Printf("choice=%x, score=%d\n", cho, choiceResults[cho[0]-1])
	}

	require.Equal(t, totalChoiceCnt, backupVotePaperCnt)
	require.Equal(t, backupVotePaperCnt, votepaper.GetVotePaperCnt())
}
