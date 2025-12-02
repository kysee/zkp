package zk_beacon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	bls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	"github.com/stretchr/testify/require"
)

type SyncCommittee struct {
	Period  string   `json:"period"`
	Pubkeys []string `json:"pubkeys"`
}

type SyncAggregate struct {
	SyncCommitteeBits      string `json:"sync_committee_bits"`
	SyncCommitteeSignature string `json:"sync_committee_signature"`
}

type BeaconBlockHeader struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	BodyRoot      string `json:"body_root"`
}

type ExecutionPayloadHeader struct {
	ParentHash       string `json:"parent_hash"`
	FeeRecipient     string `json:"fee_recipient"`
	StateRoot        string `json:"state_root"`
	ReceiptsRoot     string `json:"receipts_root"`
	LogsBloom        string `json:"logs_bloom"`
	PrevRandao       string `json:"prev_randao"`
	BlockNumber      string `json:"block_number"`
	GasLimit         string `json:"gas_limit"`
	GasUsed          string `json:"gas_used"`
	Timestamp        string `json:"timestamp"`
	ExtraData        string `json:"extra_data"`
	BaseFeePerGas    string `json:"base_fee_per_gas"`
	BlockHash        string `json:"block_hash"`
	TransactionsRoot string `json:"transactions_root"`
	WithdrawalsRoot  string `json:"withdrawals_root"`
	BlobGasUsed      string `json:"blob_gas_used"`
	ExcessBlobGas    string `json:"excess_blob_gas"`
}

type LightClientHeader struct {
	Beacon          BeaconBlockHeader      `json:"beacon"`
	Execution       ExecutionPayloadHeader `json:"execution"`
	ExecutionBranch []string               `json:"execution_branch"`
}

type NextSyncCommittee struct {
	Pubkeys []string `json:"pubkeys"`
}

type LightClientUpdate struct {
	Data struct {
		AttestedHeader    LightClientHeader `json:"attested_header"`
		NextSyncCommittee NextSyncCommittee `json:"next_sync_committee"`
		SyncAggregate     SyncAggregate     `json:"sync_aggregate"`
		SignatureSlot     string            `json:"signature_slot"`
	} `json:"data"`
}

func init() {
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(err)
	}
	if err := bls.SetETHmode(bls.EthModeDraft07); err != nil {
		panic(err)
	}
}

func hexToBytes(hexStr string) ([]byte, error) {
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}
	return hex.DecodeString(hexStr)
}

func parseSyncCommitteeBits(bitsHex string) ([]bool, error) {
	bitsBytes, err := hexToBytes(bitsHex)
	if err != nil {
		return nil, err
	}

	bits := make([]bool, 512)
	for i := 0; i < 512; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		if byteIndex < len(bitsBytes) {
			bits[i] = (bitsBytes[byteIndex] & (1 << bitIndex)) != 0
		}
	}
	return bits, nil
}

func aggregatePublicKeys(pubkeys []string, bits []bool) (*bls.PublicKey, error) {
	var aggPubkey *bls.PublicKey

	count := 0
	for i, participate := range bits {
		if !participate || i >= len(pubkeys) {
			continue
		}

		pubkeyBytes, err := hexToBytes(pubkeys[i])
		if err != nil {
			return nil, fmt.Errorf("failed to decode pubkey %d: %v", i, err)
		}

		var pubkey bls.PublicKey
		if err := pubkey.Deserialize(pubkeyBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize pubkey %d: %v", i, err)
		}

		if aggPubkey == nil {
			aggPubkey = &pubkey
		} else {
			aggPubkey.Add(&pubkey)
		}
		count++
	}

	if aggPubkey == nil {
		return nil, fmt.Errorf("no public keys to aggregate")
	}

	//t.Logf("Aggregated %d public keys\n", count)
	return aggPubkey, nil
}

func computeSigningRoot(header *LightClientHeader, signatureSlot string) ([]byte, error) {
	// Parse beacon block header fields
	slot, _ := strconv.ParseUint(header.Beacon.Slot, 10, 64)
	proposerIndex, _ := strconv.ParseUint(header.Beacon.ProposerIndex, 10, 64)

	parentRoot, err := hexToBytes(header.Beacon.ParentRoot)
	if err != nil {
		return nil, err
	}

	stateRoot, err := hexToBytes(header.Beacon.StateRoot)
	if err != nil {
		return nil, err
	}

	bodyRoot, err := hexToBytes(header.Beacon.BodyRoot)
	if err != nil {
		return nil, err
	}

	// Create beacon block header using zrnt types
	beaconHeader := common.BeaconBlockHeader{
		Slot:          common.Slot(slot),
		ProposerIndex: common.ValidatorIndex(proposerIndex),
		ParentRoot:    *(*common.Root)(parentRoot),
		StateRoot:     *(*common.Root)(stateRoot),
		BodyRoot:      *(*common.Root)(bodyRoot),
	}

	// Compute the block root (SSZ hash tree root)
	blockRoot := beaconHeader.HashTreeRoot(tree.GetHashFn())

	// For sync committee signatures, we need to compute the signing root
	// signing_root = compute_signing_root(block_root, domain)

	// DOMAIN_SYNC_COMMITTEE = DomainType([7, 0, 0, 0])
	domainType := common.BLSDomainType{0x07, 0x00, 0x00, 0x00}

	// Genesis validators root (network-specific)
	genesisValidatorsRoot := common.Root{}
	genesisValidatorsRootBytes, _ := hex.DecodeString("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
	copy(genesisValidatorsRoot[:], genesisValidatorsRootBytes)

	// Fork version (Fulu fork: 0x90000075)
	forkVersion := common.Version{0x90, 0x00, 0x00, 0x75}

	// Compute domain using zrnt library
	domain := common.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot)

	// Compute signing root using zrnt library
	signingRoot := common.ComputeSigningRoot(blockRoot, domain)

	return signingRoot[:], nil
}

func verifySyncAggregate(syncCommittee *SyncCommittee, update *LightClientUpdate) error {
	// Parse sync committee bits
	bits, err := parseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)
	if err != nil {
		return fmt.Errorf("failed to parse sync committee bits: %v", err)
	}

	// Aggregate public keys
	aggPubkey, err := aggregatePublicKeys(syncCommittee.Pubkeys, bits)
	if err != nil {
		return fmt.Errorf("failed to aggregate public keys: %v", err)
	}

	// Parse signature
	sigBytes, err := hexToBytes(update.Data.SyncAggregate.SyncCommitteeSignature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	var signature bls.Sign
	if err := signature.Deserialize(sigBytes); err != nil {
		return fmt.Errorf("failed to deserialize signature: %v", err)
	}

	// Compute signing root
	signingRoot, err := computeSigningRoot(&update.Data.AttestedHeader, update.Data.SignatureSlot)
	if err != nil {
		return fmt.Errorf("failed to compute signing root: %v", err)
	}

	// Verify signature
	if !signature.VerifyByte(aggPubkey, signingRoot) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func TestVerifySyncAggregate(t *testing.T) {
	// Load sync committee
	syncCommitteeFile, err := os.ReadFile("./curr-sync-committee.json")
	require.NoError(t, err, "Failed to read sync committee file")

	var syncCommittee SyncCommittee
	err = json.Unmarshal(syncCommitteeFile, &syncCommittee)
	require.NoError(t, err, "Failed to parse sync committee JSON")

	t.Logf("Loaded sync committee for period %s with %d pubkeys\n",
		syncCommittee.Period, len(syncCommittee.Pubkeys))

	// Load light client update
	updateFile, err := os.ReadFile("./lcupdate.json")
	require.NoError(t, err, "Failed to read light client update file")

	var update LightClientUpdate
	err = json.Unmarshal(updateFile, &update)
	require.NoError(t, err, "Failed to parse light client update JSON")

	t.Logf("Loaded light client update for slot %s\n", update.Data.AttestedHeader.Beacon.Slot)

	// Verify sync aggregate
	err = verifySyncAggregate(&syncCommittee, &update)
	require.NoError(t, err, "Failed to verify sync aggregate")

	t.Log("Verification SUCCEEDED!")
}
