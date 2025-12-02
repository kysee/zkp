package zk_beacon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/kysee/zkp/zk-beacon/circuit"
	"github.com/stretchr/testify/require"
)

func TestSyncAggregateVerifier(t *testing.T) {
	// Load light client update
	updateData, err := os.ReadFile("lcupdate.json")
	require.NoError(t, err, "Failed to read lcupdate.json")

	var update LightClientUpdateJSON
	err = json.Unmarshal(updateData, &update)
	require.NoError(t, err, "Failed to parse lcupdate.json")

	// Load current sync committee from curr-sync-committee.json
	syncCommitteeData, err := os.ReadFile("curr-sync-committee.json")
	require.NoError(t, err, "Failed to read curr-sync-committee.json")

	var syncCommittee SyncCommittee
	err = json.Unmarshal(syncCommitteeData, &syncCommittee)
	require.NoError(t, err, "Failed to parse curr-sync-committee.json")

	t.Logf("Loaded sync committee for period %s with %d pubkeys",
		syncCommittee.Period, len(syncCommittee.Pubkeys))

	// Expected block root
	expectedBlockRoot, err := hexToBytes32("0x14d44edfc2367e5a117bffcaebc821a431cdd45ec2fcc6c1389fb45a90702b97")
	require.NoError(t, err, "Failed to parse expected block root")

	// Genesis validators root
	genesisValidatorsRoot, err := hexToBytes32("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
	require.NoError(t, err, "Failed to parse genesis validators root")

	// Fork version (Fulu: 0x90000075)
	forkVersion := [4]byte{0x90, 0x00, 0x00, 0x75}

	// Domain type for DOMAIN_SYNC_COMMITTEE
	domainType := [4]byte{0x07, 0x00, 0x00, 0x00}

	// Parse participation bits
	participationBits, err := parseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)
	require.NoError(t, err, "Failed to parse participation bits")

	// Parse aggregated signature (G2 point on BLS12-381)
	sigBytes, err := hexToBytes(update.Data.SyncAggregate.SyncCommitteeSignature)
	require.NoError(t, err, "Failed to parse signature")

	var aggregatedSigNative bls12381.G2Affine
	_, err = aggregatedSigNative.SetBytes(sigBytes)
	require.NoError(t, err, "Failed to deserialize aggregated signature")

	aggregatedSig := sw_bls12381.NewG2Affine(aggregatedSigNative)

	// Load validator public keys from curr-sync-committee.json
	var validatorPubKeys [512]sw_bls12381.G1Affine
	for i := 0; i < 512 && i < len(syncCommittee.Pubkeys); i++ {
		pubkeyBytes, err := hexToBytes(syncCommittee.Pubkeys[i])
		require.NoError(t, err, "Failed to parse validator pubkey %d", i)

		var pubkeyNative bls12381.G1Affine
		_, err = pubkeyNative.SetBytes(pubkeyBytes)
		require.NoError(t, err, "Failed to deserialize validator pubkey %d", i)

		validatorPubKeys[i] = sw_bls12381.NewG1Affine(pubkeyNative)
	}

	// Create witness
	var witness circuit.SyncAggregateVerifier

	// Beacon header from attested_header.beacon
	beacon := update.Data.AttestedHeader.Beacon
	slot, err := strconv.ParseUint(beacon.Slot, 10, 64)
	require.NoError(t, err, "Failed to parse slot")

	proposerIndex, err := strconv.ParseUint(beacon.ProposerIndex, 10, 64)
	require.NoError(t, err, "Failed to parse proposer_index")

	parentRoot, err := hexToBytes32(beacon.ParentRoot)
	require.NoError(t, err, "Failed to parse parent_root")

	stateRoot, err := hexToBytes32(beacon.StateRoot)
	require.NoError(t, err, "Failed to parse state_root")

	bodyRoot, err := hexToBytes32(beacon.BodyRoot)
	require.NoError(t, err, "Failed to parse body_root")

	t.Logf("Beacon header: slot=%d, proposer=%d", slot, proposerIndex)

	// Assign beacon header
	witness.Slot = slot
	witness.ProposerIndex = proposerIndex
	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = parentRoot[i]
		witness.StateRoot[i] = stateRoot[i]
		witness.BodyRoot[i] = bodyRoot[i]
	}

	// Assign sync committee data
	witness.ValidatorPubKeys = validatorPubKeys

	// Assign participation bits
	participationCount := 0
	for i := 0; i < 512; i++ {
		if participationBits[i] {
			witness.ParticipationBits[i] = 1
			participationCount++
		} else {
			witness.ParticipationBits[i] = 0
		}
	}
	t.Logf("Participation: %d / 512 validators", participationCount)

	// Assign aggregated signature
	witness.AggregatedSig = aggregatedSig

	// Assign domain constants
	for i := 0; i < 4; i++ {
		witness.DomainType[i] = domainType[i]
		witness.ForkVersion[i] = forkVersion[i]
	}
	for i := 0; i < 32; i++ {
		witness.GenesisValidatorsRoot[i] = genesisValidatorsRoot[i]
	}

	// Assign expected block root (public input)
	for i := 0; i < 32; i++ {
		witness.BlockRoot[i] = expectedBlockRoot[i]
	}

	t.Logf("Expected BlockRoot: 0x%x", expectedBlockRoot)

	// === OPTIMIZATION: Compute hash-to-curve OUTSIDE circuit ===
	// This saves ~500,000 constraints by using native BLS12-381 operations

	// Step 1: Compute signing root outside circuit (using native SHA256)
	signingRoot := makeSigningRoot(expectedBlockRoot, domainType, forkVersion, genesisValidatorsRoot)
	t.Logf("Signing root: 0x%x", signingRoot)

	// Step 2: Hash to G2 using native BLS12-381 library
	// This is the expensive operation we avoid doing in-circuit
	messageHashNative, err := hashToG2BLS(signingRoot[:])
	require.NoError(t, err, "Failed to hash to G2")

	// Convert to circuit type
	witness.MessageHash = sw_bls12381.NewG2Affine(messageHashNative)
	t.Log("✓ Hash-to-curve computed outside circuit (saves ~500k constraints)")

	// Step 1: Compile circuit
	t.Log("Compiling circuit...")
	var circuitDef circuit.SyncAggregateVerifier

	// Compile with BN254 scalar field (for emulated BLS12-381)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitDef)
	require.NoError(t, err, "Failed to compile circuit")
	t.Logf("✓ Circuit compiled: %d constraints", ccs.GetNbConstraints())

	// Step 2: Setup (generate proving and verifying keys)
	t.Log("Generating proving and verifying keys...")
	pk, vk, err := groth16.Setup(ccs)
	require.NoError(t, err, "Failed to setup")
	t.Log("✓ Setup complete")

	// Step 3: Create witness
	fullWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Step 4: Generate proof
	t.Log("Generating proof...")
	proof, err := groth16.Prove(ccs, pk, fullWitness)
	require.NoError(t, err, "Failed to generate proof")
	t.Log("✓ Proof generated")

	// Step 5: Verify proof
	t.Log("Verifying proof...")
	publicWitness, err := fullWitness.Public()
	require.NoError(t, err, "Failed to extract public witness")

	err = groth16.Verify(proof, vk, publicWitness)
	require.NoError(t, err, "Failed to verify proof")
	t.Log("✓ Proof verified successfully!")

	t.Log("\n=== Sync Aggregate Verification Complete ===")
	t.Logf("Block Root: 0x%x", expectedBlockRoot)
	t.Logf("Validators participated: %d / 512", participationCount)
	t.Log("The zero-knowledge proof confirms:")
	t.Log("  1. Correct SSZ block root computation")
	t.Log("  2. Valid sync committee aggregation")
	t.Log("  3. Valid BLS signature from participating validators")
}

// makeSigningRoot computes the signing root for BLS signature verification
// This replicates the logic from the circuit but using native Go operations
func makeSigningRoot(blockRoot [32]byte, domainType, forkVersion [4]byte, genesisValidatorsRoot [32]byte) [32]byte {
	// Step 1: Compute fork_data_root
	// fork_data_root = hash_tree_root(ForkData(fork_version, genesis_validators_root))

	// Create fork version chunk (4 bytes + 28 zeros)
	var forkVersionChunk [32]byte
	copy(forkVersionChunk[:4], forkVersion[:])

	// Hash fork version chunk with genesis validators root
	forkDataRoot := sha256Hash(forkVersionChunk[:], genesisValidatorsRoot[:])

	// Step 2: Compute domain = domain_type (4 bytes) + first 28 bytes of fork_data_root
	var domain [32]byte
	copy(domain[:4], domainType[:])
	copy(domain[4:], forkDataRoot[:28])

	// Step 3: Compute signing_root = hash_tree_root(SigningData(block_root, domain))
	signingRoot := sha256Hash(blockRoot[:], domain[:])

	return signingRoot
}

// sha256Hash computes SHA256(left || right) for SSZ merkleization
func sha256Hash(left, right []byte) [32]byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// hashToG2BLS performs hash-to-curve mapping from bytes to G2 point
// This uses the BLS signature domain separation tag as specified in the Ethereum spec
func hashToG2BLS(message []byte) (bls12381.G2Affine, error) {
	// Use Ethereum's BLS signature domain separation tag
	// As specified in: https://github.com/ethereum/consensus-specs
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

	// Perform hash-to-curve using gnark-crypto's implementation
	// HashToG2 already returns G2Affine, no conversion needed
	result, err := bls12381.HashToG2(message, dst)
	if err != nil {
		return bls12381.G2Affine{}, fmt.Errorf("failed to hash to G2: %w", err)
	}

	return result, nil
}
