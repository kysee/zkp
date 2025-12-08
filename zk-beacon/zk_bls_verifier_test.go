package zk_beacon

import (
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

// Global variables for circuit compilation and setup (initialized once in init())
var (
	blsVerifierCCS constraint.ConstraintSystem
	blsVerifierPK  groth16.ProvingKey
	blsVerifierVK  groth16.VerifyingKey

	// Prepare domain parameters
	domainType                    = []byte{0x07, 0x00, 0x00, 0x00} // DOMAIN_SYNC_COMMITTEE
	forkVersion                   = []byte{0x90, 0x00, 0x00, 0x75} // Fulu fork
	genesisValidatorsRootBytes, _ = types.HexToBytes("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
)

// init compiles the circuit and performs setup once for all tests
func init() {
	//
	// Compile circuit
	var err error

	ccsPath := "./.build/BLSVerifierCircuit.ccs"
	pkPath := "./.build/BLSVerifierCircuit.pk"
	vkPath := "./.build/BLSVerifierCircuit.vk"

	// Step 1: Circuit compile
	fCcs, err := os.Open(ccsPath)
	defer fCcs.Close()

	if err != nil {
		fmt.Println("Compiling BLSVerifierCircuit circuit...")
		// Compile with BN254 scalar field (for emulated BLS12-381)
		blsVerifierCCS, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.BLSVerifierCircuit{})
		if err != nil {
			panic(err)
		}
		fCcs, _ = os.Create(ccsPath)
		_, _ = blsVerifierCCS.WriteTo(fCcs)
	} else {
		fmt.Println("Loading BLSVerifierCircuit circuit...")

		blsVerifierCCS = groth16.NewCS(ecc.BN254)
		_, err = blsVerifierCCS.ReadFrom(fCcs)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("✓ Circuit has %d constraints\n", blsVerifierCCS.GetNbConstraints())

	// Step 2: Setup (generate proving and verifying keys)
	fpk, err0 := os.Open(pkPath)
	defer fpk.Close()
	fvk, err1 := os.Open(vkPath)
	defer fvk.Close()

	if err0 != nil || err1 != nil {
		fmt.Println("Generating proving and verifying keys...")
		blsVerifierPK, blsVerifierVK, err = groth16.Setup(blsVerifierCCS)
		if err != nil {
			panic(err)
		}
		fpk, _ = os.Create(pkPath)
		_, _ = blsVerifierPK.WriteTo(fpk)

		fvk, _ = os.Create(vkPath)
		_, _ = blsVerifierVK.WriteTo(fvk)
	} else {
		fmt.Println("Loading proving and verifying keys...")
		blsVerifierPK = groth16.NewProvingKey(ecc.BN254)
		blsVerifierVK = groth16.NewVerifyingKey(ecc.BN254)
		if _, err := blsVerifierPK.ReadFrom(fpk); err != nil {
			panic(err)
		}
		if _, err := blsVerifierVK.ReadFrom(fvk); err != nil {
			panic(err)
		}
	}
	fmt.Println("✓ Setup complete")
}

// assignNextSyncCommitteeToWitness computes next_sync_committee root and assigns it along with
// next_sync_committee_branch to the witness
func assignNextSyncCommitteeToWitness(
	update *types.LightClientUpdate,
	witness *circuit.BLSVerifierCircuit,
) {
	// Compute next_sync_committee root
	nextSCRoot := update.Data.NextSyncCommittee.HashTreeRoot(configs.Mainnet, tree.GetHashFn())

	// Assign next_sync_committee root (public input)
	for i := 0; i < 32; i++ {
		witness.NextSyncCommitteeRoot[i] = nextSCRoot[i]
	}

	// Assign next_sync_committee_branch (private input)
	for i := 0; i < 6; i++ {
		for j := 0; j < 32; j++ {
			witness.NextSyncCommitteeBranch[i][j] = update.Data.NextSyncCommitteeBranch[i][j]
		}
	}
}

func TestBLSVerifierCircuit(t *testing.T) {
	// Load sync committee
	syncCommitteeFile, err := os.ReadFile("data/curr-sc.json")
	require.NoError(t, err, "Failed to read sync committee file")

	var syncCommittee types.SyncCommittee
	err = json.Unmarshal(syncCommitteeFile, &syncCommittee)
	require.NoError(t, err, "Failed to parse sync committee JSON")

	t.Logf("Loaded sync committee for period %s with %d pubkeys",
		syncCommittee.Period, len(syncCommittee.Pubkeys))

	// Load light client update
	updateFile, err := os.ReadFile("data/lcupdate.json")
	require.NoError(t, err, "Failed to read light client update file")

	var update types.LightClientUpdate
	err = json.Unmarshal(updateFile, &update)
	require.NoError(t, err, "Failed to parse light client update JSON")

	t.Logf("Loaded light client update for slot %s", update.Data.AttestedHeader.Beacon.Slot)

	// Parse sync committee bits
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse signature (G2 point)
	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]
	var signature bls12381.G2Affine
	_, err = signature.SetBytes(sigBytes)
	require.NoError(t, err, "Failed to deserialize signature")

	// Parse all 512 public keys and aggregate them based on sync_committee_bits
	require.Equal(t, 512, len(syncCommittee.Pubkeys), "Expected 512 pubkeys")
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, err = pubkeys[i].SetBytes(pubkeyBytes)
		require.NoError(t, err, "Failed to deserialize pubkey %d", i)
	}

	// Aggregate public keys based on sync_committee_bits (OUTSIDE the circuit)
	var aggregatedPubKey bls12381.G1Affine
	aggregatedPubKey.Set(&bls12381.G1Affine{}) // Initialize to identity
	for i := 0; i < 512; i++ {
		if bits[i] {
			aggregatedPubKey.Add(&aggregatedPubKey, &pubkeys[i])
		}
	}

	// Create witness
	witness := &circuit.BLSVerifierCircuit{}

	// Assign BeaconBlockHeader fields
	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)

	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = update.Data.AttestedHeader.Beacon.ParentRoot[i]
		witness.StateRoot[i] = update.Data.AttestedHeader.Beacon.StateRoot[i]
		witness.BodyRoot[i] = update.Data.AttestedHeader.Beacon.BodyRoot[i]
	}

	// Compute domain externally using types.ComputeDomain
	domain, err := types.ComputeDomain(domainType, forkVersion, genesisValidatorsRootBytes)
	require.NoError(t, err, "Failed to compute domain")

	// Assign domain to witness
	for i := 0; i < 32; i++ {
		witness.Domain[i] = domain[i]
	}

	// Assign aggregated public key (PUBLIC INPUT)
	witness.AggregatedPubKey = sw_bls12381.NewG1Affine(aggregatedPubKey)

	// Assign BLS signature using gnark's conversion function
	witness.AggregatedSig = sw_bls12381.NewG2Affine(signature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Test proof generation and verification
	t.Run("Generate and Verify Proof", func(t *testing.T) {
		// Create full witness
		fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
		require.NoError(t, err, "Failed to create witness")

		// Create proof using pre-compiled circuit and keys
		proof, err := groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
		require.NoError(t, err, "Proof generation failed")

		t.Logf("Proof generated successfully")

		// Extract public inputs for verification
		publicWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
		require.NoError(t, err, "Failed to create public witness")

		// Verify proof using pre-compiled verifying key
		err = groth16.Verify(proof, blsVerifierVK, publicWitness)
		require.NoError(t, err, "Proof verification failed")

		t.Logf("✓ Proof verification SUCCEEDED!")
	})
}

func TestBLSVerifierCircuitInvalidSignature(t *testing.T) {
	// Load sync committee
	syncCommitteeFile, err := os.ReadFile("data/curr-sc.json")
	require.NoError(t, err, "Failed to read sync committee file")

	var syncCommittee types.SyncCommittee
	err = json.Unmarshal(syncCommitteeFile, &syncCommittee)
	require.NoError(t, err, "Failed to parse sync committee JSON")

	// Load light client update
	updateFile, err := os.ReadFile("data/lcupdate.json")
	require.NoError(t, err, "Failed to read light client update file")

	var update types.LightClientUpdate
	err = json.Unmarshal(updateFile, &update)
	require.NoError(t, err, "Failed to parse light client update JSON")

	// Parse sync committee bits
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse all 512 public keys and aggregate them
	require.Equal(t, 512, len(syncCommittee.Pubkeys), "Expected 512 pubkeys")
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, err = pubkeys[i].SetBytes(pubkeyBytes)
		require.NoError(t, err, "Failed to deserialize pubkey %d", i)
	}

	// Aggregate public keys based on sync_committee_bits (OUTSIDE the circuit)
	var aggregatedPubKey bls12381.G1Affine
	aggregatedPubKey.Set(&bls12381.G1Affine{}) // Initialize to identity
	for i := 0; i < 512; i++ {
		if bits[i] {
			aggregatedPubKey.Add(&aggregatedPubKey, &pubkeys[i])
		}
	}

	// Use INVALID signature (random G2 point)
	var invalidSignature bls12381.G2Affine
	invalidSignature.X.SetRandom()
	invalidSignature.Y.SetRandom()

	// Create witness with invalid signature
	witness := &circuit.BLSVerifierCircuit{}

	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)

	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = update.Data.AttestedHeader.Beacon.ParentRoot[i]
		witness.StateRoot[i] = update.Data.AttestedHeader.Beacon.StateRoot[i]
		witness.BodyRoot[i] = update.Data.AttestedHeader.Beacon.BodyRoot[i]
	}

	// Compute domain externally
	domain, err := types.ComputeDomain(domainType, forkVersion, genesisValidatorsRootBytes)
	require.NoError(t, err, "Failed to compute domain")
	for i := 0; i < 32; i++ {
		witness.Domain[i] = domain[i]
	}

	// Assign aggregated public key (PUBLIC INPUT)
	witness.AggregatedPubKey = sw_bls12381.NewG1Affine(aggregatedPubKey)

	// Assign INVALID signature
	witness.AggregatedSig = sw_bls12381.NewG2Affine(invalidSignature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Create witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Try to create proof with invalid signature - this should fail
	proof, err := groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
	if err != nil {
		t.Logf("✓ Proof generation correctly failed with invalid signature: %v", err)
		return
	}

	// If proof was generated, verification should fail
	publicWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	require.NoError(t, err, "Failed to create public witness")

	err = groth16.Verify(proof, blsVerifierVK, publicWitness)
	if err != nil {
		t.Logf("✓ Proof verification correctly failed with invalid signature")
	} else {
		t.Fatal("Expected verification to fail with invalid signature, but it succeeded!")
	}
}

func TestBLSVerifierCircuitInvalidBlockRoot(t *testing.T) {
	// Load sync committee
	syncCommitteeFile, err := os.ReadFile("data/curr-sc.json")
	require.NoError(t, err, "Failed to read sync committee file")

	var syncCommittee types.SyncCommittee
	err = json.Unmarshal(syncCommitteeFile, &syncCommittee)
	require.NoError(t, err, "Failed to parse sync committee JSON")

	// Load light client update
	updateFile, err := os.ReadFile("data/lcupdate.json")
	require.NoError(t, err, "Failed to read light client update file")

	var update types.LightClientUpdate
	err = json.Unmarshal(updateFile, &update)
	require.NoError(t, err, "Failed to parse light client update JSON")

	// Parse sync committee bits
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse all 512 public keys and aggregate them
	require.Equal(t, 512, len(syncCommittee.Pubkeys), "Expected 512 pubkeys")
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, err = pubkeys[i].SetBytes(pubkeyBytes)
		require.NoError(t, err, "Failed to deserialize pubkey %d", i)
	}

	// Aggregate public keys based on sync_committee_bits (OUTSIDE the circuit)
	var aggregatedPubKey bls12381.G1Affine
	aggregatedPubKey.Set(&bls12381.G1Affine{}) // Initialize to identity
	for i := 0; i < 512; i++ {
		if bits[i] {
			aggregatedPubKey.Add(&aggregatedPubKey, &pubkeys[i])
		}
	}

	// Parse signature
	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]
	var signature bls12381.G2Affine
	_, err = signature.SetBytes(sigBytes)
	require.NoError(t, err, "Failed to deserialize signature")

	// Use INVALID block root
	var invalidBlockRoot [32]byte
	for i := 0; i < 32; i++ {
		invalidBlockRoot[i] = 0xFF
	}

	// Create witness with invalid block root
	witness := &circuit.BLSVerifierCircuit{}

	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)

	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = update.Data.AttestedHeader.Beacon.ParentRoot[i]
		witness.StateRoot[i] = update.Data.AttestedHeader.Beacon.StateRoot[i]
		witness.BodyRoot[i] = invalidBlockRoot[i] //update.Data.AttestedHeader.Beacon.BodyRoot[i]
	}

	// Compute domain externally
	domain, err := types.ComputeDomain(domainType, forkVersion, genesisValidatorsRootBytes)
	require.NoError(t, err, "Failed to compute domain")
	for i := 0; i < 32; i++ {
		witness.Domain[i] = domain[i]
	}

	// Assign aggregated public key (PUBLIC INPUT)
	witness.AggregatedPubKey = sw_bls12381.NewG1Affine(aggregatedPubKey)

	witness.AggregatedSig = sw_bls12381.NewG2Affine(signature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Create witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Try to create proof with invalid block root - this should fail
	_, err = groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
	require.Error(t, err, "Expected proof generation to fail with invalid block root")

	t.Logf("✓ Proof generation correctly failed with invalid block root: %v", err)
}

// Benchmark the circuit
func BenchmarkBLSVerifierCircuit(b *testing.B) {
	// Load test data
	syncCommitteeFile, err := os.ReadFile("data/curr-sc.json")
	if err != nil {
		b.Skip("Test data not available")
	}

	var syncCommittee types.SyncCommittee
	json.Unmarshal(syncCommitteeFile, &syncCommittee)

	updateFile, _ := os.ReadFile("data/lcupdate.json")
	var update types.LightClientUpdate
	json.Unmarshal(updateFile, &update)

	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)

	// Parse all 512 public keys and aggregate them
	var pubkeys [512]bls12381.G1Affine
	for i := 0; i < 512; i++ {
		pubkeyBytes := syncCommittee.Pubkeys[i][:]
		_, _ = pubkeys[i].SetBytes(pubkeyBytes)
	}

	// Aggregate public keys based on sync_committee_bits (OUTSIDE the circuit)
	var aggregatedPubKey bls12381.G1Affine
	aggregatedPubKey.Set(&bls12381.G1Affine{}) // Initialize to identity
	for i := 0; i < 512; i++ {
		if bits[i] {
			aggregatedPubKey.Add(&aggregatedPubKey, &pubkeys[i])
		}
	}

	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]
	var signature bls12381.G2Affine
	signature.SetBytes(sigBytes)

	witness := &circuit.BLSVerifierCircuit{}
	witness.Slot = uint64(update.Data.AttestedHeader.Beacon.Slot)
	witness.ProposerIndex = uint64(update.Data.AttestedHeader.Beacon.ProposerIndex)

	for i := 0; i < 32; i++ {
		witness.ParentRoot[i] = update.Data.AttestedHeader.Beacon.ParentRoot[i]
		witness.StateRoot[i] = update.Data.AttestedHeader.Beacon.StateRoot[i]
		witness.BodyRoot[i] = update.Data.AttestedHeader.Beacon.BodyRoot[i]
	}

	// Compute domain externally
	domain, _ := types.ComputeDomain(domainType, forkVersion, genesisValidatorsRootBytes)
	for i := 0; i < 32; i++ {
		witness.Domain[i] = domain[i]
	}

	// Assign aggregated public key (PUBLIC INPUT)
	witness.AggregatedPubKey = sw_bls12381.NewG1Affine(aggregatedPubKey)

	witness.AggregatedSig = sw_bls12381.NewG2Affine(signature)

	// Assign next_sync_committee root and branch to witness
	assignNextSyncCommitteeToWitness(&update, witness)

	// Create witness once
	fullWitness, _ := frontend.NewWitness(witness, ecc.BN254.ScalarField())

	b.Run("ProofGeneration", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Generate proof once for verification benchmark
	proof, _ := groth16.Prove(blsVerifierCCS, blsVerifierPK, fullWitness)
	publicWitness, _ := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())

	b.Run("ProofVerification", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := groth16.Verify(proof, blsVerifierVK, publicWitness)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
