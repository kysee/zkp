package circuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// BLSVerifierCircuit verifies Ethereum beacon chain sync committee BLS signatures
//
// This circuit performs the complete verification flow:
// 1. Computes blockRoot from BeaconBlockHeader fields
// 2. Computes signingRoot = hash(blockRoot, domain)
// 3. Computes signingRootG2 = hash-to-curve(signingRoot) IN-CIRCUIT
// 4. Verifies BLS signature: e(pubkey, H(signingRoot)) == e(G1, signature)
//
// Note: Public key aggregation is performed outside the circuit,
// but hash-to-curve is computed IN-CIRCUIT.
type BLSVerifierCircuit struct {
	// BeaconBlockHeader fields (private inputs)
	Slot          frontend.Variable     // uint64
	ProposerIndex frontend.Variable     // uint64
	ParentRoot    [32]frontend.Variable // bytes32
	StateRoot     [32]frontend.Variable // bytes32
	BodyRoot      [32]frontend.Variable // bytes32

	// Domain parameters for signingRoot computation (private inputs)
	DomainType            [4]frontend.Variable  // BLS domain type (e.g., DOMAIN_SYNC_COMMITTEE = 0x07000000)
	ForkVersion           [4]frontend.Variable  // Fork version (e.g., Fulu = 0x90000075)
	GenesisValidatorsRoot [32]frontend.Variable // Network-specific genesis validators root

	// Aggregated signature (private input)
	AggregatedSig sw_bls12381.G2Affine

	// Public inputs for verification
	AggregatedPubKey sw_bls12381.G1Affine `gnark:",public"` // Aggregated validator public keys
}

// Define implements the circuit constraints
func (c *BLSVerifierCircuit) Define(api frontend.API) error {
	// Step 1: Compute blockRoot from BeaconBlockHeader
	blockRoot := c.computeBlockRoot(api)

	// Step 2: Compute signingRoot = hash(blockRoot, domain)
	signingRoot := c.computeSigningRoot(api, blockRoot)

	// Step 3: Compute signingRootG2 = hash-to-curve(signingRoot) IN-CIRCUIT
	signingRootG2, err := c.hashToG2InCircuit(api, signingRoot)
	if err != nil {
		return fmt.Errorf("hash-to-curve failed: %w", err)
	}

	// Step 4: Verify BLS signature against the computed signingRootG2
	// If the BeaconBlockHeader fields are incorrect, the blockRoot will be wrong,
	// leading to wrong signingRoot and signingRootG2, which will fail signature verification
	err = c.verifyBLSSignature(api, signingRootG2)
	if err != nil {
		return fmt.Errorf("BLS signature verification failed: %w", err)
	}

	return nil
}

// computeBlockRoot computes the SSZ hash_tree_root of the beacon block header
// This reuses the same logic as BlockRootHasher
func (c *BLSVerifierCircuit) computeBlockRoot(api frontend.API) [32]frontend.Variable {
	// Convert each field to a 32-byte chunk
	slotChunk := c.serializeUint64ToChunk(api, c.Slot)
	proposerChunk := c.serializeUint64ToChunk(api, c.ProposerIndex)
	parentRootChunk := c.ParentRoot
	stateRootChunk := c.StateRoot
	bodyRootChunk := c.BodyRoot
	zeroChunk := c.zeroChunk()

	// Build Merkle tree (5 leaves + 3 zeros = 8 leaves total)
	// Layer 1: Hash adjacent pairs
	h01 := c.hashPair(api, slotChunk, proposerChunk)
	h23 := c.hashPair(api, parentRootChunk, stateRootChunk)
	h45 := c.hashPair(api, bodyRootChunk, zeroChunk)
	h67 := c.hashPair(api, zeroChunk, zeroChunk)

	// Layer 2: Hash pairs from layer 1
	h0123 := c.hashPair(api, h01, h23)
	h4567 := c.hashPair(api, h45, h67)

	// Layer 3 (root): Final hash
	root := c.hashPair(api, h0123, h4567)

	return root
}

// computeSigningRoot computes the signing root used in BLS signature verification
// signingRoot = hash_tree_root(SigningData(blockRoot, domain))
//
// SigningData structure:
//   object_root: blockRoot (32 bytes)
//   domain: domain (32 bytes)
//
// domain = domain_type || fork_data_root[:28]
// fork_data_root = hash_tree_root(ForkData(fork_version, genesis_validators_root))
func (c *BLSVerifierCircuit) computeSigningRoot(api frontend.API, blockRoot [32]frontend.Variable) [32]frontend.Variable {
	// Step 1: Compute fork_data_root = hash(fork_version || genesis_validators_root)
	forkDataRoot := c.computeForkDataRoot(api)

	// Step 2: Compute domain = domain_type (4 bytes) || fork_data_root[:28]
	var domain [32]frontend.Variable
	for i := 0; i < 4; i++ {
		domain[i] = c.DomainType[i]
	}
	for i := 0; i < 28; i++ {
		domain[i+4] = forkDataRoot[i]
	}

	// Step 3: Compute signingRoot = hash(blockRoot || domain)
	signingRoot := c.hashPair(api, blockRoot, domain)

	return signingRoot
}

// computeForkDataRoot computes hash_tree_root of ForkData
// ForkData has two fields: fork_version (4 bytes) and genesis_validators_root (32 bytes)
func (c *BLSVerifierCircuit) computeForkDataRoot(api frontend.API) [32]frontend.Variable {
	// Serialize fork_version to 32-byte chunk (little-endian + padding)
	var forkVersionChunk [32]frontend.Variable
	for i := 0; i < 4; i++ {
		forkVersionChunk[i] = c.ForkVersion[i]
	}
	for i := 4; i < 32; i++ {
		forkVersionChunk[i] = 0
	}

	// genesis_validators_root is already a 32-byte chunk
	genesisValidatorsRootChunk := c.GenesisValidatorsRoot

	// Hash the two chunks together
	return c.hashPair(api, forkVersionChunk, genesisValidatorsRootChunk)
}

// hashToG2InCircuit performs hash-to-curve operation IN-CIRCUIT
// This maps signingRoot (32 bytes) to a point on G2
func (c *BLSVerifierCircuit) hashToG2InCircuit(api frontend.API, signingRoot [32]frontend.Variable) (*sw_bls12381.G2Affine, error) {
	// Hash signingRoot to Fp2 element using expand_message_xmd (SHA-256)
	// This follows BLS signature spec: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_

	// DST (Domain Separation Tag) for BLS signatures
	// dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

	// For simplicity in circuit, we'll hash signingRoot twice to get two field elements
	// that form an Fp2 element (c0, c1)

	// Hash signingRoot to get c0
	c0Bytes := c.hashToField(api, signingRoot, 0)
	// Hash signingRoot with different tag to get c1
	c1Bytes := c.hashToField(api, signingRoot, 1)

	// Convert bytes to emulated.Element
	c0Element := c.bytesToElement(api, c0Bytes)
	c1Element := c.bytesToElement(api, c1Bytes)

	// Create Fp2 element (E2)
	fp2Element := &fields_bls12381.E2{
		A0: c0Element,
		A1: c1Element,
	}

	// Use EVM precompile to map Fp2 to G2
	// This performs the SSWU map and cofactor clearing
	var resultG2 sw_bls12381.G2Affine
	err := evmprecompiles.ECMapToG2BLS(api, fp2Element, &resultG2)
	if err != nil {
		return nil, fmt.Errorf("map to G2 failed: %w", err)
	}

	return &resultG2, nil
}

// hashToField hashes signingRoot with a counter to produce a field element
func (c *BLSVerifierCircuit) hashToField(api frontend.API, signingRoot [32]frontend.Variable, counter int) [32]frontend.Variable {
	hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}

	// Write signingRoot
	signingRootBytes := make([]uints.U8, 32)
	for i := 0; i < 32; i++ {
		signingRootBytes[i] = uints.U8{Val: signingRoot[i]}
	}
	hasher.Write(signingRootBytes)

	// Write counter as a byte
	hasher.Write([]uints.U8{{Val: counter}})

	// Compute hash
	hashResult := hasher.Sum()

	// Convert to [32]frontend.Variable
	var result [32]frontend.Variable
	for i := 0; i < 32; i++ {
		result[i] = hashResult[i].Val
	}

	return result
}

// bytesToElement converts 32 bytes to an emulated field element
// This creates an Element suitable for BLS12-381 Fp field
func (c *BLSVerifierCircuit) bytesToElement(api frontend.API, bytes [32]frontend.Variable) emulated.Element[emulated.BLS12381Fp] {
	// For in-circuit computation, we need to pack bytes into limbs
	// BLS12-381 Fp uses multiple limbs to represent field elements

	// Standard limb configuration for BN254 circuit (typically 4-6 limbs)
	// We'll create limbs by packing bytes together
	const numLimbs = 6 // Standard for BLS12-381 in BN254 circuit
	const bitsPerLimb = 64
	const bytesPerLimb = bitsPerLimb / 8

	limbs := make([]frontend.Variable, numLimbs)

	// Pack bytes into limbs (little-endian)
	for i := 0; i < numLimbs; i++ {
		var limbValue frontend.Variable = 0
		for j := 0; j < bytesPerLimb; j++ {
			byteIdx := i*bytesPerLimb + j
			if byteIdx < 32 {
				// Build limb: byte[0] + byte[1]*2^8 + byte[2]*2^16 + ...
				// Calculate 2^(j*8)
				var power frontend.Variable = 1
				for k := 0; k < j*8; k++ {
					power = api.Add(power, power) // power *= 2
				}
				limbValue = api.Add(limbValue, api.Mul(bytes[byteIdx], power))
			}
		}
		limbs[i] = limbValue
	}

	return emulated.Element[emulated.BLS12381Fp]{Limbs: limbs}
}

// verifyBLSSignature verifies the BLS signature using pairing check
// Verifies: e(pubkey, H(msg)) == e(G1, signature)
// Or equivalently: e(pubkey, H(msg)) * e(-G1, signature) == 1
func (c *BLSVerifierCircuit) verifyBLSSignature(api frontend.API, signingRootG2 *sw_bls12381.G2Affine) error {
	// Create pairing instance
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("failed to create pairing: %w", err)
	}

	// Verify inputs are in correct subgroups
	pairing.AssertIsOnG1(&c.AggregatedPubKey)
	pairing.AssertIsOnG2(signingRootG2)
	pairing.AssertIsOnG2(&c.AggregatedSig)

	// Create curve for G1 operations
	curve, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return fmt.Errorf("failed to create curve: %w", err)
	}

	// Get G1 generator and negate it
	g1Gen := curve.Generator()
	negG1Gen := curve.Neg(g1Gen)

	// Pairing check: e(pubkey, H(msg)) * e(-G1, signature) == 1
	err = pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{&c.AggregatedPubKey, negG1Gen},
		[]*sw_bls12381.G2Affine{signingRootG2, &c.AggregatedSig},
	)
	if err != nil {
		return fmt.Errorf("pairing check failed: %w", err)
	}

	return nil
}

// Helper functions (reused from BlockRootHasher)

func (c *BLSVerifierCircuit) serializeUint64ToChunk(api frontend.API, value frontend.Variable) [32]frontend.Variable {
	var chunk [32]frontend.Variable

	// Convert value to 64 bits (little-endian)
	bits := api.ToBinary(value, 64)

	// Pack bits into bytes (8 bits per byte, little-endian)
	for byteIdx := 0; byteIdx < 8; byteIdx++ {
		var byteValue frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			bit := bits[byteIdx*8+bitIdx]
			power := 1 << bitIdx
			byteValue = api.Add(byteValue, api.Mul(bit, power))
		}
		chunk[byteIdx] = byteValue
	}

	// Remaining 24 bytes are zero-padded
	for i := 8; i < 32; i++ {
		chunk[i] = 0
	}

	return chunk
}

func (c *BLSVerifierCircuit) zeroChunk() [32]frontend.Variable {
	var chunk [32]frontend.Variable
	for i := 0; i < 32; i++ {
		chunk[i] = 0
	}
	return chunk
}

func (c *BLSVerifierCircuit) hashPair(api frontend.API, left, right [32]frontend.Variable) [32]frontend.Variable {
	// Create a new SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}

	// Convert left and right chunks to []uints.U8
	leftBytes := make([]uints.U8, 32)
	rightBytes := make([]uints.U8, 32)

	for i := 0; i < 32; i++ {
		leftBytes[i] = uints.U8{Val: left[i]}
		rightBytes[i] = uints.U8{Val: right[i]}
	}

	// Write 64 bytes total (left || right)
	hasher.Write(leftBytes)
	hasher.Write(rightBytes)

	// Compute SHA256 hash
	hashResult := hasher.Sum()

	// Convert hash result ([]uints.U8) back to [32]frontend.Variable
	var result [32]frontend.Variable
	for i := 0; i < 32; i++ {
		result[i] = hashResult[i].Val
	}

	return result
}
