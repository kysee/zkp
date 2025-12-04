package zk_beacon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/kysee/zkp/zk-beacon/types"
	zrntcommon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	"github.com/stretchr/testify/require"
)

// Updated to use gnark-crypto instead of herumi/bls
// This is Ethereum-compatible and pure Go (no CGO warnings)

func computeSigningRoot(header *zrntcommon.BeaconBlockHeader) ([]byte, error) {
	// Compute the block root (SSZ hash tree root)
	blockRoot := header.HashTreeRoot(tree.GetHashFn())

	// For sync committee signatures, we need to compute the signing root
	// signing_root = compute_signing_root(block_root, domain)

	// DOMAIN_SYNC_COMMITTEE = DomainType([7, 0, 0, 0])
	domainType := zrntcommon.BLSDomainType{0x07, 0x00, 0x00, 0x00}

	// Genesis validators root (network-specific - Holesky testnet)
	genesisValidatorsRoot := zrntcommon.Root{}
	genesisValidatorsRootBytes, _ := hex.DecodeString("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
	copy(genesisValidatorsRoot[:], genesisValidatorsRootBytes)

	// Fork version (Fulu fork: 0x90000075)
	forkVersion := zrntcommon.Version{0x90, 0x00, 0x00, 0x75}

	// Compute domain using zrnt library
	domain := zrntcommon.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot)

	// Compute signing root using zrnt library
	signingRoot := zrntcommon.ComputeSigningRoot(blockRoot, domain)

	return signingRoot[:], nil
}

func verifySyncAggregate(syncCommittee *types.SyncCommittee, update *types.LightClientUpdate) error {
	// Parse sync committee bits
	bits := types.ParseSyncCommitteeBits(update.Data.SyncAggregate.SyncCommitteeBits)
	// Aggregate public keys using gnark-crypto
	aggPubkey, err := types.AggregatePublicKeys(syncCommittee.Pubkeys, bits)
	if err != nil {
		return fmt.Errorf("failed to aggregate public keys: %v", err)
	}

	// Parse signature (G2 point)
	sigBytes := update.Data.SyncAggregate.SyncCommitteeSignature[:]

	var signature bls12381.G2Affine
	_, err = signature.SetBytes(sigBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize signature: %v", err)
	}

	// Compute signing root
	signingRoot, err := computeSigningRoot(&update.Data.AttestedHeader.Beacon)
	if err != nil {
		return fmt.Errorf("failed to compute signing root: %v", err)
	}

	// Hash to G2 (BLS signature scheme)
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
	messageHash, err := bls12381.HashToG2(signingRoot, dst)
	if err != nil {
		return fmt.Errorf("failed to hash to G2: %v", err)
	}

	// Verify BLS signature: e(pubkey, H(msg)) == e(G1, signature)
	// Or equivalently: e(pubkey, H(msg)) * e(-G1, signature) == 1

	// Get G1 generator and negate it
	_, _, g1Gen, _ := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)

	valid, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{aggPubkey, negG1},
		[]bls12381.G2Affine{messageHash, signature},
	)
	if err != nil {
		return fmt.Errorf("pairing check error: %v", err)
	}

	if !valid {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func TestVerifySyncAggregate(t *testing.T) {
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

	// Verify sync aggregate
	err = verifySyncAggregate(&syncCommittee, &update)
	require.NoError(t, err, "Failed to verify sync aggregate")

	t.Log("✓ Signature verification SUCCEEDED using gnark-crypto!")
}
