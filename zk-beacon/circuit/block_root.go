package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// BlockRootHasher computes the SSZ hash_tree_root of a beacon block header
// This follows the SSZ (Simple Serialize) specification used in Ethereum consensus layer
type BlockRootHasher struct {
	// BeaconBlockHeader fields
	Slot          frontend.Variable     // uint64
	ProposerIndex frontend.Variable     // uint64
	ParentRoot    [32]frontend.Variable // bytes32
	StateRoot     [32]frontend.Variable // bytes32
	BodyRoot      [32]frontend.Variable // bytes32

	// Expected SSZ root (public input for verification)
	ExpectedRoot [32]frontend.Variable `gnark:",public"`
}

// Define implements the gnark circuit constraint definition
// It computes the SSZ hash_tree_root and verifies it matches the expected root
func (h *BlockRootHasher) Define(api frontend.API) error {
	// Compute the SSZ root
	computedRoot := h.ComputeSSZRoot(api)

	// Verify computed root matches expected root
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedRoot[i], h.ExpectedRoot[i])
	}

	return nil
}

// ComputeSSZRoot computes the SSZ hash_tree_root of the beacon block header
//
// SSZ merkleization process for BeaconBlockHeader:
// 1. Convert each field to a 32-byte chunk (little-endian for integers)
// 2. Build a binary Merkle tree with these chunks as leaves
// 3. Pad to next power of 2 (5 fields -> 8 leaves with 3 zero chunks)
// 4. Hash pairs bottom-up to compute the root
func (h *BlockRootHasher) ComputeSSZRoot(api frontend.API) [32]frontend.Variable {
	// Step 1: Convert each field to a 32-byte chunk
	slotChunk := h.serializeUint64ToChunk(api, h.Slot)
	proposerChunk := h.serializeUint64ToChunk(api, h.ProposerIndex)
	parentRootChunk := h.ParentRoot
	stateRootChunk := h.StateRoot
	bodyRootChunk := h.BodyRoot
	zeroChunk := h.zeroChunk()

	// Step 2: Build Merkle tree (5 leaves + 3 zeros = 8 leaves total)
	// Layer 0 (leaves): [slot, proposer, parent, state, body, 0, 0, 0]

	// Layer 1: Hash adjacent pairs
	// h01 = hash(slot_chunk || proposer_chunk)
	h01 := h.hashPair(api, slotChunk, proposerChunk)

	// h23 = hash(parent_root || state_root)
	h23 := h.hashPair(api, parentRootChunk, stateRootChunk)

	// h45 = hash(body_root || zero)
	h45 := h.hashPair(api, bodyRootChunk, zeroChunk)

	// h67 = hash(zero || zero)
	h67 := h.hashPair(api, zeroChunk, zeroChunk)

	// Layer 2: Hash pairs from layer 1
	// h0123 = hash(h01 || h23)
	h0123 := h.hashPair(api, h01, h23)

	// h4567 = hash(h45 || h67)
	h4567 := h.hashPair(api, h45, h67)

	// Layer 3 (root): Final hash
	// root = hash(h0123 || h4567)
	root := h.hashPair(api, h0123, h4567)

	return root
}

// serializeUint64ToChunk converts a uint64 value to a 32-byte chunk (little-endian + padding)
func (h *BlockRootHasher) serializeUint64ToChunk(api frontend.API, value frontend.Variable) [32]frontend.Variable {
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

// zeroChunk returns a 32-byte chunk filled with zeros
func (h *BlockRootHasher) zeroChunk() [32]frontend.Variable {
	var chunk [32]frontend.Variable
	for i := 0; i < 32; i++ {
		chunk[i] = 0
	}
	return chunk
}

// hashPair computes SHA256(left || right) where left and right are 32-byte chunks
func (h *BlockRootHasher) hashPair(api frontend.API, left, right [32]frontend.Variable) [32]frontend.Variable {
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

// AssignPrvInput assigns values to the beacon block header fields
func (h *BlockRootHasher) AssignPrvInput(
	slot uint64,
	proposerIndex uint64,
	parentRoot [32]byte,
	stateRoot [32]byte,
	bodyRoot [32]byte,
) {
	h.Slot = slot
	h.ProposerIndex = proposerIndex

	for i := 0; i < 32; i++ {
		h.ParentRoot[i] = parentRoot[i]
		h.StateRoot[i] = stateRoot[i]
		h.BodyRoot[i] = bodyRoot[i]
	}
}

// AssignPubInput assigns the expected SSZ root for verification
func (h *BlockRootHasher) AssignPubInput(root [32]byte) {
	for i := 0; i < 32; i++ {
		h.ExpectedRoot[i] = root[i]
	}
}
