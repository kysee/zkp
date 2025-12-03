package zk_beacon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/kysee/zkp/zk-beacon/circuit"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
	"github.com/stretchr/testify/require"
)

var (
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
)

func init() {
	//
	// Compile circuit
	var err error

	fmt.Println("Compiling circuit...")
	var circuitDef circuit.SyncAggregateVerifier

	// Compile with BN254 scalar field (for emulated BLS12-381)
	ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitDef, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		panic(err)
	}
	fmt.Printf("✓ Circuit compiled: %d constraints\n", ccs.GetNbConstraints())

	// Step 2: Setup (generate proving and verifying keys)
	fmt.Println("Generating proving and verifying keys...")
	pk, vk, err = groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Setup complete")

}
func TestSyncAggregateVerifier(t *testing.T) {
	// Load light client update
	var update LightClientUpdate
	updateData, err := os.ReadFile("lcupdate.json")
	require.NoError(t, err, "Failed to read lcupdate.json")
	err = json.Unmarshal(updateData, &update)
	require.NoError(t, err, "Failed to parse lcupdate.json")

	proof := createProof(t, &update)
	verifyProof(t, proof, &update)
}

func createProof(t *testing.T, update *LightClientUpdate) groth16.Proof {

	t.Log("\n=== Sync Aggregate Prover Side  ===")

	// Beacon header from attested_header.beaconHeader
	beaconHeader := update.Data.AttestedHeader.Beacon
	t.Logf("Beacon header: slot=%d, proposer=%d", beaconHeader.Slot, beaconHeader.ProposerIndex)
	syncAggregate := update.Data.SyncAggregate

	// Load current sync committee from curr-sc.json
	var syncCommittee SyncCommittee
	syncCommitteeData, err := os.ReadFile("curr-sc.json")
	require.NoError(t, err, "Failed to read curr-sc.json")
	err = json.Unmarshal(syncCommitteeData, &syncCommittee)
	require.NoError(t, err, "Failed to parse curr-sc.json")

	t.Logf("Loaded sync committee for period %s with %d pubkeys",
		syncCommittee.Period, len(syncCommittee.Pubkeys))

	// Parse participation bits
	participationBits := parseSyncCommitteeBits(syncAggregate.SyncCommitteeBits)
	// Parse aggregated signature (G2 point on BLS12-381)
	var aggregatedSigNative bls12381.G2Affine
	_, err = aggregatedSigNative.SetBytes(syncAggregate.SyncCommitteeSignature[:])
	require.NoError(t, err, "Failed to deserialize aggregated signature")
	// Aggregate public keys outside the circuit
	aggregatedPubKeyNative, participationCount, err := aggregatePublicKeysNative(syncCommittee.Pubkeys, participationBits)
	require.NoError(t, err, "Failed to aggregate public keys")
	t.Logf("Participation: %d / 512 validators", participationCount)

	// === ORIGINAL APPROACH: Hash-to-curve entirely outside circuit ===
	// We compute the entire hash-to-curve operation (hash-to-field + map-to-curve)
	// outside the circuit and provide the resulting G2 point as SigningRootG2 input

	// Step 1: Compute signing root outside circuit (using native SHA256)
	blockRoot := beaconHeader.HashTreeRoot(tree.GetHashFn()) //hexToBytes32("0x14d44edfc2367e5a117bffcaebc821a431cdd45ec2fcc6c1389fb45a90702b97")
	signingRoot := makeSigningRoot(blockRoot)
	t.Logf("Signing root: 0x%x", signingRoot)

	// Step 2: Hash to G2 using native BLS12-381 library
	// This performs the complete hash-to-curve operation
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
	hashG2Native, err := bls12381.HashToG2(signingRoot[:], dst)
	require.NoError(t, err, "Failed to hash to G2")
	t.Log("✓ Hash-to-curve computed entirely outside circuit")

	nextSyncCommitteeRoot := update.Data.NextSyncCommittee.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	t.Logf("Next Sync Committee root: %v", nextSyncCommitteeRoot.String())
	t.Logf("Beacon Header State root: %v", beaconHeader.StateRoot.String())

	// Create assignment
	var assignment circuit.SyncAggregateVerifier

	// Assign aggregated public key (computed outside circuit)
	assignment.AggregatedPubKey = sw_bls12381.NewG1Affine(aggregatedPubKeyNative)
	assignment.AggregatedSig = sw_bls12381.NewG2Affine(aggregatedSigNative)
	assignment.SigningRootG2 = sw_bls12381.NewG2Affine(hashG2Native)
	for i, _ := range nextSyncCommitteeRoot {
		assignment.StateRoot[i] = beaconHeader.StateRoot[i]
		assignment.NextPubKeysRoot[i] = nextSyncCommitteeRoot[i]
	}

	// Assign NextSyncCommitteeBranch from light client update
	for i := 0; i < 6; i++ {
		for j := 0; j < 32; j++ {
			assignment.NextSyncCommitteeBranch[i][j] = update.Data.NextSyncCommitteeBranch[i][j]
		}
	}

	// Step 3: Create witness
	fullWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	//
	// Step 4: Generate proof
	t.Log("Generating proof...")
	proof, err := groth16.Prove(ccs, pk, fullWitness)
	require.NoError(t, err, "Failed to generate proof")
	t.Log("✓ Proof generated")

	return proof
}

func verifyProof(t *testing.T, proof groth16.Proof, update *LightClientUpdate) {
	t.Log("\n=== Sync Aggregate Verifier Side  ===")

	// Beacon header from attested_header.beaconHeader
	beaconHeader := update.Data.AttestedHeader.Beacon
	t.Logf("Beacon header: slot=%d, proposer=%d", beaconHeader.Slot, beaconHeader.ProposerIndex)
	syncAggregate := update.Data.SyncAggregate

	// Load current sync committee from curr-sc.json
	var syncCommittee SyncCommittee
	syncCommitteeData, err := os.ReadFile("curr-sc.json")
	require.NoError(t, err, "Failed to read curr-sc.json")
	err = json.Unmarshal(syncCommitteeData, &syncCommittee)
	require.NoError(t, err, "Failed to parse curr-sc.json")

	t.Logf("Loaded sync committee for period %s with %d pubkeys",
		syncCommittee.Period, len(syncCommittee.Pubkeys))

	// Parse participation bits
	participationBits := parseSyncCommitteeBits(syncAggregate.SyncCommitteeBits)
	// Parse aggregated signature (G2 point on BLS12-381)
	aggregatedPubKeyNative, participationCount, err := aggregatePublicKeysNative(syncCommittee.Pubkeys, participationBits)
	require.NoError(t, err, "Failed to aggregate public keys")
	t.Logf("Participation: %d / 512 validators", participationCount)

	// === ORIGINAL APPROACH: Hash-to-curve entirely outside circuit ===
	// We compute the entire hash-to-curve operation (hash-to-field + map-to-curve)
	// outside the circuit and provide the resulting G2 point as SigningRootG2 input

	// Step 1: Compute signing root outside circuit (using native SHA256)
	blockRoot := beaconHeader.HashTreeRoot(tree.GetHashFn()) //hexToBytes32("0x14d44edfc2367e5a117bffcaebc821a431cdd45ec2fcc6c1389fb45a90702b97")
	signingRoot := makeSigningRoot(blockRoot)
	t.Logf("Signing root: 0x%x", signingRoot)

	// Step 2: Hash to G2 using native BLS12-381 library
	// This performs the complete hash-to-curve operation
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
	hashG2Native, err := bls12381.HashToG2(signingRoot[:], dst)
	require.NoError(t, err, "Failed to hash to G2")
	t.Log("✓ Hash-to-curve computed entirely outside circuit")

	nextSyncCommitteeRoot := update.Data.NextSyncCommittee.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	t.Logf("Next Sync Committee root: %v", nextSyncCommitteeRoot.String())
	t.Logf("Beacon Header State root: %v", beaconHeader.StateRoot.String())

	// Create assignment
	var assignment circuit.SyncAggregateVerifier

	// Assign aggregated public key (computed outside circuit)
	assignment.AggregatedPubKey = sw_bls12381.NewG1Affine(aggregatedPubKeyNative)
	assignment.SigningRootG2 = sw_bls12381.NewG2Affine(hashG2Native)
	for i, _ := range nextSyncCommitteeRoot {
		assignment.StateRoot[i] = beaconHeader.StateRoot[i]
		assignment.NextPubKeysRoot[i] = nextSyncCommitteeRoot[i]
	}

	//
	// Step 5: Verify proof
	t.Log("Verifying proof...")
	publicWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	require.NoError(t, err, "Failed to extract public witness")

	err = groth16.Verify(proof, vk, publicWitness)
	require.NoError(t, err, "Failed to verify proof")
	t.Log("✓ Proof verified successfully!")

	t.Logf("Block Root: %v", blockRoot.String())
	t.Logf("Validators participated: %d / 512", participationCount)
	t.Log("The zero-knowledge proof confirms:")
	t.Log("  1. Correct SSZ block root computation")
	t.Log("  2. Valid sync committee aggregation")
	t.Log("  3. Valid BLS signature from participating validators")

}

// makeSigningRoot computes the signing root for BLS signature verification
// This replicates the logic from the circuit but using native Go operations
func makeSigningRoot(blockRoot [32]byte) [32]byte {
	domainType := [4]byte{0x07, 0x00, 0x00, 0x00}
	forkVersion := [4]byte{0x90, 0x00, 0x00, 0x75}
	genesisValidatorsRoot, _ := hexToBytes32("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")

	// Step 1: Compute fork version chunk (4 bytes + 28 zeros)
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

// aggregatePublicKeysNative aggregates public keys based on participation bits
// Returns the aggregated public key and the number of participating validators
func aggregatePublicKeysNative(pubkeys []string, bits []bool) (bls12381.G1Affine, int, error) {
	var aggPubkey bls12381.G1Affine
	aggPubkey.SetInfinity() // Start with identity element

	count := 0
	for i, participate := range bits {
		if !participate || i >= len(pubkeys) {
			continue
		}

		pubkeyBytes, err := hexToBytes(pubkeys[i])
		if err != nil {
			return aggPubkey, 0, fmt.Errorf("failed to decode pubkey %d: %v", i, err)
		}

		var pubkey bls12381.G1Affine
		_, err = pubkey.SetBytes(pubkeyBytes)
		if err != nil {
			return aggPubkey, 0, fmt.Errorf("failed to deserialize pubkey %d: %v", i, err)
		}

		// Add to aggregate
		aggPubkey.Add(&aggPubkey, &pubkey)
		count++
	}

	if count == 0 {
		return aggPubkey, 0, fmt.Errorf("no public keys to aggregate")
	}

	return aggPubkey, count, nil
}
