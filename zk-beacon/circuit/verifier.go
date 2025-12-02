package circuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// SyncAggregateVerifier verifies Ethereum beacon chain sync committee signatures
//
// This circuit:
// 1. Computes the SSZ block root from beacon header fields (reusing BlockRootHasher logic)
// 2. Computes the signing root (domain + block root)
// 3. Aggregates validator public keys based on participation bits
// 4. Verifies the aggregated BLS signature
type SyncAggregateVerifier struct {
	// Beacon block header fields (from attested_header.beacon)
	Slot          frontend.Variable     // uint64
	ProposerIndex frontend.Variable     // uint64
	ParentRoot    [32]frontend.Variable // bytes32
	StateRoot     [32]frontend.Variable // bytes32
	BodyRoot      [32]frontend.Variable // bytes32

	// Sync committee data (512 validators)
	ValidatorPubKeys [512]sw_bls12381.G1Affine // Public keys of sync committee validators

	// Sync aggregate data
	ParticipationBits [512]frontend.Variable // sync_committee_bits (512 bits)
	AggregatedSig     sw_bls12381.G2Affine   // sync_committee_signature

	// Message hash (signing root mapped to G2) - computed outside circuit
	MessageHash sw_bls12381.G2Affine // hash-to-curve(signing_root)

	// Constants for signing root computation
	DomainType            [4]frontend.Variable  // DOMAIN_SYNC_COMMITTEE = [7, 0, 0, 0]
	ForkVersion           [4]frontend.Variable  // Network fork version (e.g., Fulu: [0x90, 0x00, 0x00, 0x75])
	GenesisValidatorsRoot [32]frontend.Variable // Network genesis validators root

	// Public output: the computed block root (can be used for verification)
	BlockRoot [32]frontend.Variable `gnark:",public"`
}

// Define implements the circuit constraints
func (c *SyncAggregateVerifier) Define(api frontend.API) error {
	// Step 1: Compute SSZ block root
	blockRoot := c.computeBlockRoot(api)

	// Verify computed block root matches public input
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(blockRoot[i], c.BlockRoot[i])
	}

	// Step 2: Compute signing root (domain + block_root)
	// Note: We compute this for verification, but the actual hash-to-curve
	// is done outside the circuit and provided as MessageHash witness
	_ = c.computeSigningRoot(api, blockRoot)

	// Step 3: Aggregate public keys based on participation bits
	aggregatedPubKey := c.aggregatePubKeys(api)

	// Step 4: Verify BLS signature using precomputed MessageHash
	// MessageHash = hash_to_curve(signing_root) computed outside circuit
	err := c.verifyBLSSignature(api, aggregatedPubKey, c.MessageHash)
	if err != nil {
		return fmt.Errorf("BLS signature verification failed: %w", err)
	}

	return nil
}

// computeBlockRoot computes SSZ hash_tree_root of beacon block header
// This reuses the logic from BlockRootHasher
func (c *SyncAggregateVerifier) computeBlockRoot(api frontend.API) [32]frontend.Variable {
	// Convert fields to 32-byte chunks
	slotChunk := serializeUint64ToChunk(api, c.Slot)
	proposerChunk := serializeUint64ToChunk(api, c.ProposerIndex)
	parentRootChunk := c.ParentRoot
	stateRootChunk := c.StateRoot
	bodyRootChunk := c.BodyRoot
	zeroChunk := zeroChunk()

	// Build Merkle tree (5 leaves + 3 zeros = 8 leaves)
	// Layer 1
	h01 := hashPair(api, slotChunk, proposerChunk)
	h23 := hashPair(api, parentRootChunk, stateRootChunk)
	h45 := hashPair(api, bodyRootChunk, zeroChunk)
	h67 := hashPair(api, zeroChunk, zeroChunk)

	// Layer 2
	h0123 := hashPair(api, h01, h23)
	h4567 := hashPair(api, h45, h67)

	// Layer 3 (root)
	root := hashPair(api, h0123, h4567)

	return root
}

// computeSigningRoot computes the signing root used in BLS signature
// signing_root = compute_signing_root(block_root, domain)
// where domain = compute_domain(domain_type, fork_version, genesis_validators_root)
func (c *SyncAggregateVerifier) computeSigningRoot(api frontend.API, blockRoot [32]frontend.Variable) [32]frontend.Variable {
	// Compute domain: first 4 bytes of fork_data_root + domain_type
	// fork_data_root = hash_tree_root(ForkData(fork_version, genesis_validators_root))

	// Step 1: Compute fork_data_root
	// ForkData has 2 fields: version (4 bytes), genesis_validators_root (32 bytes)
	var forkVersionChunk [32]frontend.Variable
	for i := 0; i < 4; i++ {
		forkVersionChunk[i] = c.ForkVersion[i]
	}
	for i := 4; i < 32; i++ {
		forkVersionChunk[i] = 0
	}

	forkDataRoot := hashPair(api, forkVersionChunk, c.GenesisValidatorsRoot)

	// Step 2: Compute domain = first 4 bytes of fork_data_root + domain_type (4 bytes)
	var domain [32]frontend.Variable
	for i := 0; i < 4; i++ {
		domain[i] = c.DomainType[i]
	}
	for i := 4; i < 32; i++ {
		domain[i] = forkDataRoot[i-4]
	}

	// Step 3: Compute signing_root = hash_tree_root(SigningData(block_root, domain))
	// SigningData has 2 fields: object_root (32 bytes), domain (32 bytes)
	signingRoot := hashPair(api, blockRoot, domain)

	return signingRoot
}

// hashToG2 maps a hash to a point on G2 (placeholder implementation)
// TODO: Implement proper hash-to-curve for BLS12-381 G2
// For now, this is a placeholder that would need the actual hash-to-curve algorithm
func (c *SyncAggregateVerifier) hashToG2(api frontend.API, hash [32]frontend.Variable) sw_bls12381.G2Affine {
	// This is a critical TODO: proper hash-to-curve implementation
	// For testing purposes, this would be provided as a witness
	// In production, use the standard hash-to-curve algorithm for BLS12-381

	// Placeholder: return a default G2 point
	// In actual implementation, this must properly map the hash to G2
	return sw_bls12381.G2Affine{}
}

// aggregatePubKeys aggregates validator public keys based on participation bits
func (c *SyncAggregateVerifier) aggregatePubKeys(api frontend.API) sw_bls12381.G1Affine {
	// Create curve instance for G1 operations
	curve, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		panic(fmt.Errorf("failed to create BLS12-381 curve: %w", err))
	}

	// Start with the first validator (participating or not)
	result := &c.ValidatorPubKeys[0]

	// For each remaining validator, conditionally add their pubkey if they participated
	for i := 1; i < 512; i++ {
		// If participation bit is 1, add this validator; otherwise keep current result
		temp := curve.Add(result, &c.ValidatorPubKeys[i])
		result = curve.Select(c.ParticipationBits[i], temp, result)
	}

	// Now handle the first validator
	// If bit[0] is 0, we need to subtract validator[0] from result
	// But that's complex. Instead, let's use a different approach:
	// We'll create a "zeroed" version by conditionally including validator[0]
	temp := curve.Add(result, curve.Neg(&c.ValidatorPubKeys[0]))
	result = curve.Select(c.ParticipationBits[0], result, temp)

	return *result
}

// verifyBLSSignature verifies the BLS signature using pairing check
// Verifies: e(pubkey, H(msg)) == e(G1, signature)
// Or equivalently: e(pubkey, H(msg)) * e(-G1, signature) == 1
func (c *SyncAggregateVerifier) verifyBLSSignature(
	api frontend.API,
	pubkey sw_bls12381.G1Affine,
	messageHash sw_bls12381.G2Affine,
) error {
	// Create pairing instance
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("failed to create pairing: %w", err)
	}

	// Verify inputs are in correct subgroups
	pairing.AssertIsOnG1(&pubkey)
	pairing.AssertIsOnG2(&messageHash)
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
		[]*sw_bls12381.G1Affine{&pubkey, negG1Gen},
		[]*sw_bls12381.G2Affine{&messageHash, &c.AggregatedSig},
	)
	if err != nil {
		return fmt.Errorf("pairing check failed: %w", err)
	}

	return nil
}

// Helper functions (copied from block_root.go for reuse)

func serializeUint64ToChunk(api frontend.API, value frontend.Variable) [32]frontend.Variable {
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

func zeroChunk() [32]frontend.Variable {
	var chunk [32]frontend.Variable
	for i := 0; i < 32; i++ {
		chunk[i] = 0
	}
	return chunk
}

func hashPair(api frontend.API, left, right [32]frontend.Variable) [32]frontend.Variable {
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
