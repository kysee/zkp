package types

import (
	"crypto/sha256"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	zrntaltair "github.com/protolambda/zrnt/eth2/beacon/altair"
	zrntcommon "github.com/protolambda/zrnt/eth2/beacon/common"
)

type SyncCommittee struct {
	Period  string   `json:"period"`
	Pubkeys []string `json:"pubkeys"`
}

type SyncAggregate struct {
	SyncCommitteeBits      string `json:"sync_committee_bits"`
	SyncCommitteeSignature string `json:"sync_committee_signature"`
}

type LightClientUpdate struct {
	Data struct {
		AttestedHeader struct {
			Beacon          zrntcommon.BeaconBlockHeader `json:"beacon"`
			Execution       ExecutionPayloadHeader       `json:"execution"`
			ExecutionBranch []string                     `json:"execution_branch"`
		} `json:"attested_header"`
		NextSyncCommittee       zrntcommon.SyncCommittee `json:"next_sync_committee"`
		NextSyncCommitteeBranch [6]zrntcommon.Root       `json:"next_sync_committee_branch"`
		SyncAggregate           zrntaltair.SyncAggregate `json:"sync_aggregate"`
		SignatureSlot           string                   `json:"signature_slot"`
	} `json:"data"`
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

func ParseSyncCommitteeBits(bitsBytes []byte) []bool {
	bits := make([]bool, 512)
	for i := 0; i < 512; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		if byteIndex < len(bitsBytes) {
			bits[i] = (bitsBytes[byteIndex] & (1 << bitIndex)) != 0
		}
	}
	return bits
}

// Aggregate public keys using gnark-crypto (native BLS12-381)
func AggregatePublicKeys(pubkeys []string, bits []bool) (bls12381.G1Affine, error) {
	var aggPubkey bls12381.G1Affine
	aggPubkey.SetInfinity() // Start with identity element

	count := 0
	for i, participate := range bits {
		if !participate || i >= len(pubkeys) {
			continue
		}

		pubkeyBytes, err := HexToBytes(pubkeys[i])
		if err != nil {
			return aggPubkey, fmt.Errorf("failed to decode pubkey %d: %v", i, err)
		}

		var pubkey bls12381.G1Affine
		_, err = pubkey.SetBytes(pubkeyBytes)
		if err != nil {
			return aggPubkey, fmt.Errorf("failed to deserialize pubkey %d: %v", i, err)
		}

		// Add to aggregate
		aggPubkey.Add(&aggPubkey, &pubkey)
		count++
	}

	if count == 0 {
		return aggPubkey, fmt.Errorf("no public keys to aggregate")
	}

	return aggPubkey, nil
}

// ComputeDomain computes the BLS domain for sync committee signatures
// domain = domain_type || fork_data_root[:28]
// where fork_data_root = hash_tree_root(ForkData(fork_version, genesis_validators_root))
func ComputeDomain(domainType []byte, forkVersion []byte, genesisValidatorsRoot []byte) ([32]byte, error) {
	var domain [32]byte

	// Validate input lengths
	if len(domainType) != 4 {
		return domain, fmt.Errorf("domainType must be 4 bytes, got %d", len(domainType))
	}
	if len(forkVersion) != 4 {
		return domain, fmt.Errorf("forkVersion must be 4 bytes, got %d", len(forkVersion))
	}
	if len(genesisValidatorsRoot) != 32 {
		return domain, fmt.Errorf("genesisValidatorsRoot must be 32 bytes, got %d", len(genesisValidatorsRoot))
	}

	// Step 1: Compute fork_data_root
	// Serialize fork_version as 32-byte chunk (little-endian + zero padding)
	var forkVersionChunk [32]byte
	copy(forkVersionChunk[:4], forkVersion[:4])
	// Remaining 28 bytes are already zero

	// Hash fork_version chunk with genesis_validators_root
	hasher := sha256.New()
	hasher.Write(forkVersionChunk[:])
	hasher.Write(genesisValidatorsRoot[:32])
	forkDataRoot := hasher.Sum(nil)

	// Step 2: Compute domain = domain_type (4 bytes) || fork_data_root[:28]
	copy(domain[:4], domainType[:4])
	copy(domain[4:], forkDataRoot[:28])

	return domain, nil
}
