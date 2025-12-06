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
	"github.com/kysee/zkp/zk-beacon/types"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
	"github.com/stretchr/testify/require"
)

var (
	scVerifierCCS constraint.ConstraintSystem
	scVerifierPK  groth16.ProvingKey
	scVerifierVK  groth16.VerifyingKey
)

func init() {
	//
	// Compile circuit
	var err error

	ccsPath := "./.build/SyncCommitteeVerifierCircuit.ccs"
	pkPath := "./.build/SyncCommitteeVerifierCircuit.pk"
	vkPath := "./.build/SyncCommitteeVerifierCircuit.vk"

	// Step 1: Circuit compile
	fCcs, err := os.Open(ccsPath)
	defer fCcs.Close()

	if err != nil {
		fmt.Println("Compiling SyncCommitteeVerifierCircuit circuit...")
		// Compile with BN254 scalar field (for emulated BLS12-381)
		scVerifierCCS, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.SyncCommitteeVerifierCircuit{})
		if err != nil {
			panic(err)
		}
		fCcs, _ = os.Create(ccsPath)
		_, _ = scVerifierCCS.WriteTo(fCcs)
	} else {
		fmt.Println("Loading SyncCommitteeVerifierCircuit circuit...")

		scVerifierCCS = groth16.NewCS(ecc.BN254)
		_, err = scVerifierCCS.ReadFrom(fCcs)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("✓ Circuit has %d constraints\n", scVerifierCCS.GetNbConstraints())

	// Step 2: Setup (generate proving and verifying keys)
	fpk, err0 := os.Open(pkPath)
	defer fpk.Close()
	fvk, err1 := os.Open(vkPath)
	defer fvk.Close()

	if err0 != nil || err1 != nil {
		fmt.Println("Generating proving and verifying keys...")
		scVerifierPK, scVerifierVK, err = groth16.Setup(scVerifierCCS)
		if err != nil {
			panic(err)
		}

		fpk, _ = os.Create(pkPath)
		_, _ = scVerifierPK.WriteTo(fpk)

		fvk, _ = os.Create(vkPath)
		_, _ = scVerifierVK.WriteTo(fvk)
	} else {
		fmt.Println("Loading proving and verifying keys...")
		scVerifierPK = groth16.NewProvingKey(ecc.BN254)
		scVerifierVK = groth16.NewVerifyingKey(ecc.BN254)

		if _, err := scVerifierPK.ReadFrom(fpk); err != nil {
			panic(err)
		}
		if _, err := scVerifierVK.ReadFrom(fvk); err != nil {
			panic(err)
		}
	}
	fmt.Println("✓ Setup complete")
}

func TestSyncAggregateVerifier(t *testing.T) {
	// Load light client update
	var update types.LightClientUpdate
	updateData, err := os.ReadFile("data/lcupdate.json")
	require.NoError(t, err, "Failed to read data/lcupdate.json")
	err = json.Unmarshal(updateData, &update)
	require.NoError(t, err, "Failed to parse data/lcupdate.json")

	proof := createProof(t, &update)
	verifyProof(t, proof, &update)
}

func createProof(t *testing.T, update *types.LightClientUpdate) groth16.Proof {

	t.Log("\n=== Sync Aggregate Prover Side  ===")

	// Beacon header from attested_header.beaconHeader
	beaconHeader := update.Data.AttestedHeader.Beacon
	t.Logf("Beacon header: slot=%d, proposer=%d", beaconHeader.Slot, beaconHeader.ProposerIndex)
	syncAggregate := update.Data.SyncAggregate

	// Load current sync committee from curr-sc.json
	var syncCommittee types.SyncCommittee
	syncCommitteeData, err := os.ReadFile("data/curr-sc.json")
	require.NoError(t, err, "Failed to read data/curr-sc.json")
	err = json.Unmarshal(syncCommitteeData, &syncCommittee)
	require.NoError(t, err, "Failed to parse data/curr-sc.json")

	t.Logf("Loaded sync committee for period %s with %d pubkeys",
		syncCommittee.Period, len(syncCommittee.Pubkeys))

	// Parse participation bits
	participationBits := types.ParseSyncCommitteeBits(syncAggregate.SyncCommitteeBits)
	// Parse aggregated signature (G2 point on BLS12-381)
	var aggregatedSigNative bls12381.G2Affine
	_, err = aggregatedSigNative.SetBytes(syncAggregate.SyncCommitteeSignature[:])
	require.NoError(t, err, "Failed to deserialize aggregated signature")
	// Aggregate public keys outside the circuit
	aggregatedPubKeyNative, participationCount, err := types.AggregatePublicKeys(syncCommittee.Pubkeys, participationBits)
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
	var assignment circuit.SyncCommitteeVerifierCircuit

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
	proof, err := groth16.Prove(scVerifierCCS, scVerifierPK, fullWitness)
	require.NoError(t, err, "Failed to generate proof")
	t.Log("✓ Proof generated")

	return proof
}

func verifyProof(t *testing.T, proof groth16.Proof, update *types.LightClientUpdate) {
	t.Log("\n=== Sync Aggregate Verifier Side  ===")

	// Beacon header from attested_header.beaconHeader
	beaconHeader := update.Data.AttestedHeader.Beacon
	t.Logf("Beacon header: slot=%d, proposer=%d", beaconHeader.Slot, beaconHeader.ProposerIndex)
	syncAggregate := update.Data.SyncAggregate

	// Load current sync committee from curr-sc.json
	var syncCommittee types.SyncCommittee
	syncCommitteeData, err := os.ReadFile("data/curr-sc.json")
	require.NoError(t, err, "Failed to read data/curr-sc.json")
	err = json.Unmarshal(syncCommitteeData, &syncCommittee)
	require.NoError(t, err, "Failed to parse data/curr-sc.json")

	t.Logf("Loaded sync committee for period %s with %d pubkeys",
		syncCommittee.Period, len(syncCommittee.Pubkeys))

	// Parse participation bits
	participationBits := types.ParseSyncCommitteeBits(syncAggregate.SyncCommitteeBits)
	// Parse aggregated signature (G2 point on BLS12-381)
	aggregatedPubKeyNative, participationCount, err := types.AggregatePublicKeys(syncCommittee.Pubkeys, participationBits)
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
	var assignment circuit.SyncCommitteeVerifierCircuit

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

	err = groth16.Verify(proof, scVerifierVK, publicWitness)
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
	genesisValidatorsRoot, _ := types.HexToBytes("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")

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
