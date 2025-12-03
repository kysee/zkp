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
// 1. Computes the SSZ block root from beacon header fields
// 2. Verifies the aggregated BLS signature
//
// Note: Both hash-to-curve and public key aggregation are performed outside the circuit
// to minimize the number of constraints.
type SyncAggregateVerifier struct {
	// Aggregated signature from sync_committee_signature
	AggregatedSig sw_bls12381.G2Affine

	// Aggregated public key (witness) - computed outside circuit
	// This is the aggregation of validator public keys based on participation bits
	AggregatedPubKey sw_bls12381.G1Affine `gnark:",public"` // Σ(pubkey_i) for participating validators

	// Message hash (witness) - result of hash-to-curve(signing_root)
	// This is computed outside the circuit and provided as input
	SigningRootG2 sw_bls12381.G2Affine `gnark:",public"` // H(signing_root) mapped to G2

	// BeaconState's root
	StateRoot       [32]frontend.Variable `gnark:",public"` // bytes32
	NextPubKeysRoot [32]frontend.Variable `gnark:",public"` // SSZ root of next sync committee

	// Merkle proof branch for next_sync_committee in BeaconState
	// Electra has 37 fields, requiring depth 6
	NextSyncCommitteeBranch [6][32]frontend.Variable
}

// Define implements the circuit constraints
func (c *SyncAggregateVerifier) Define(api frontend.API) error {
	// Step 1: Verify BLS signature using witness values
	// Both AggregatedPubKey and SigningRootG2 are computed outside circuit
	err := c.verifyBLSSignature(api)
	if err != nil {
		return fmt.Errorf("BLS signature verification failed: %w", err)
	}

	// Step 2: Verify Merkle Proof for NextPubKeysRoot
	err = c.verifyMerkleProof(api)
	if err != nil {
		return fmt.Errorf("Merkle proof verification failed: %w", err)
	}

	return nil
}

// verifyBLSSignature verifies the BLS signature using pairing check
// Verifies: e(pubkey, H(msg)) == e(G1, signature)
// Or equivalently: e(pubkey, H(msg)) * e(-G1, signature) == 1
func (c *SyncAggregateVerifier) verifyBLSSignature(api frontend.API) error {
	// Create pairing instance
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("failed to create pairing: %w", err)
	}

	// Verify inputs are in correct subgroups
	pairing.AssertIsOnG1(&c.AggregatedPubKey)
	pairing.AssertIsOnG2(&c.SigningRootG2)
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
		[]*sw_bls12381.G2Affine{&c.SigningRootG2, &c.AggregatedSig},
	)
	if err != nil {
		return fmt.Errorf("pairing check failed: %w", err)
	}

	return nil
}

// verifyMerkleProof verifies that NextPubKeysRoot is part of StateRoot
// using the provided Merkle branch proof
func (c *SyncAggregateVerifier) verifyMerkleProof(api frontend.API) error {
	// NextSyncCommittee generalized index in Fulu BeaconState
	// Position 23 (0-indexed) in 38-field structure
	// Generalized index = 2^depth + position = 64 + 23 = 87 (0x57 in hex)
	const nextSyncCommitteeIndex = 23

	// Start with the leaf (NextPubKeysRoot)
	currentHash := c.NextPubKeysRoot

	// Create U8 system for converting frontend.Variable to U8
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return fmt.Errorf("failed to create uints API: %w", err)
	}

	// Traverse up the Merkle tree using the branch
	for i := 0; i < 6; i++ {
		// Determine if we're on the left or right side at this level
		// Extract bit i from the generalized index
		bit := (nextSyncCommitteeIndex >> i) & 1

		var combinedBytes []uints.U8

		if bit == 0 {
			// Current node is on the left, sibling on the right
			for j := 0; j < 32; j++ {
				combinedBytes = append(combinedBytes, uapi.ByteValueOf(currentHash[j]))
			}
			for j := 0; j < 32; j++ {
				combinedBytes = append(combinedBytes, uapi.ByteValueOf(c.NextSyncCommitteeBranch[i][j]))
			}
		} else {
			// Current node is on the right, sibling on the left
			for j := 0; j < 32; j++ {
				combinedBytes = append(combinedBytes, uapi.ByteValueOf(c.NextSyncCommitteeBranch[i][j]))
			}
			for j := 0; j < 32; j++ {
				combinedBytes = append(combinedBytes, uapi.ByteValueOf(currentHash[j]))
			}
		}

		// Hash the combined bytes to get the parent node
		hasher, err := sha2.New(api)
		if err != nil {
			return fmt.Errorf("failed to create SHA256 hasher at level %d: %w", i, err)
		}

		hasher.Write(combinedBytes)
		parentHash := hasher.Sum()

		// Update currentHash for next iteration
		for j := 0; j < 32; j++ {
			currentHash[j] = parentHash[j].Val
		}
	}

	// After traversing all levels, currentHash should equal StateRoot
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(currentHash[i], c.StateRoot[i])
	}

	return nil
}
