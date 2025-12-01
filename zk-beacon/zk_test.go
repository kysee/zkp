package zk_beacon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnark_test "github.com/consensys/gnark/test"
	"github.com/kysee/zkp/zk-beacon/circuit"
	"github.com/stretchr/testify/require"
)

type BeaconBlockHeaderJSON struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	BodyRoot      string `json:"body_root"`
}

type LightClientHeaderJSON struct {
	Beacon BeaconBlockHeaderJSON `json:"beacon"`
}

type LightClientUpdateJSON struct {
	Data struct {
		AttestedHeader LightClientHeaderJSON `json:"attested_header"`
	} `json:"data"`
}

func hexToBytes32(hexStr string) ([32]byte, error) {
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], bytes)
	return result, nil
}

func TestAttestedHeaderSSZRoot(t *testing.T) {
	// Load light client update from JSON
	data, err := os.ReadFile("lcupdate.json")
	require.NoError(t, err, "Failed to read lcupdate.json")

	var update LightClientUpdateJSON
	err = json.Unmarshal(data, &update)
	require.NoError(t, err, "Failed to parse JSON")

	beacon := update.Data.AttestedHeader.Beacon

	// Parse beacon header fields
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

	// Expected SSZ root
	expectedRoot, err := hexToBytes32("0x14d44edfc2367e5a117bffcaebc821a431cdd45ec2fcc6c1389fb45a90702b97")
	require.NoError(t, err, "Failed to parse expected root")

	fmt.Printf("Slot: %d\n", slot)
	fmt.Printf("ProposerIndex: %d\n", proposerIndex)
	fmt.Printf("ParentRoot: 0x%x\n", parentRoot)
	fmt.Printf("StateRoot: 0x%x\n", stateRoot)
	fmt.Printf("BodyRoot: 0x%x\n", bodyRoot)
	fmt.Printf("ExpectedRoot: 0x%x\n", expectedRoot)

	// Create witness (assignment)
	var assignment circuit.BlockRootHasher
	assignment.AssignBeaconHeader(slot, proposerIndex, parentRoot, stateRoot, bodyRoot)
	assignment.AssignExpectedRoot(expectedRoot)

	// Test the circuit using gnark test framework
	assert := gnark_test.NewAssert(t)
	err = gnark_test.IsSolved(&circuit.BlockRootHasher{}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err, "Circuit constraints should be satisfied")

	fmt.Println("✓ Circuit constraints satisfied - SSZ root hash computation verified!")
}

func TestAttestedHeaderProofGeneration(t *testing.T) {
	// Load light client update from JSON
	data, err := os.ReadFile("lcupdate.json")
	require.NoError(t, err, "Failed to read lcupdate.json")

	var update LightClientUpdateJSON
	err = json.Unmarshal(data, &update)
	require.NoError(t, err, "Failed to parse JSON")

	beacon := update.Data.AttestedHeader.Beacon

	// Parse beacon header fields
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

	expectedRoot, err := hexToBytes32("0x14d44edfc2367e5a117bffcaebc821a431cdd45ec2fcc6c1389fb45a90702b97")
	require.NoError(t, err, "Failed to parse expected root")

	// Step 1: Compile the circuit
	fmt.Println("Compiling circuit...")
	var circuitInstance circuit.BlockRootHasher
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitInstance)
	require.NoError(t, err, "Failed to compile circuit")
	fmt.Printf("✓ Circuit compiled: %d constraints\n", ccs.GetNbConstraints())

	// Step 2: Setup (generate proving and verifying keys)
	fmt.Println("Generating proving and verifying keys...")
	pk, vk, err := groth16.Setup(ccs)
	require.NoError(t, err, "Failed to setup")
	fmt.Println("✓ Setup complete")

	// Step 3: Create witness
	var assignment circuit.BlockRootHasher
	assignment.AssignBeaconHeader(slot, proposerIndex, parentRoot, stateRoot, bodyRoot)
	assignment.AssignExpectedRoot(expectedRoot)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	require.NoError(t, err, "Failed to create witness")

	// Step 4: Generate proof
	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(ccs, pk, witness)
	require.NoError(t, err, "Failed to generate proof")
	fmt.Println("✓ Proof generated")

	// Step 5: Verify proof
	fmt.Println("Verifying proof...")
	publicWitness, err := witness.Public()
	require.NoError(t, err, "Failed to extract public witness")

	err = groth16.Verify(proof, vk, publicWitness)
	require.NoError(t, err, "Failed to verify proof")
	fmt.Println("✓ Proof verified successfully!")

	fmt.Println("\n=== Proof Generation and Verification Complete ===")
	fmt.Printf("Attested Header Slot: %d\n", slot)
	fmt.Printf("SSZ Root Hash: 0x%x\n", expectedRoot)
	fmt.Println("The zero-knowledge proof confirms the correct computation of the SSZ root hash")
	fmt.Println("without revealing the intermediate computation steps.")
}
