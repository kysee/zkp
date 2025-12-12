// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "hardhat/console.sol";
import "./ScUpdateVerifier.sol";
import "./PoseidonT3.sol";

contract LightClient {
    uint256 public period;
    bytes32 public scPubkeysHash;
    ScUpdateVerifier public verifier;

    // Beacon chain constants
    uint256 constant SLOTS_PER_EPOCH = 32;
    uint256 constant EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256;

    constructor(uint256 _initialPeriod, bytes32 _initialScPubkeysHash, address _verifierAddress) {
        period = _initialPeriod;
        scPubkeysHash = _initialScPubkeysHash;
        verifier = ScUpdateVerifier(_verifierAddress);
    }

    function updateSyncCommittee(
        uint256 slot,
        bytes calldata scBits,
        bytes calldata nextSc,
        uint256[8] calldata proof
    ) external {
        // Validate inputs
        require(scBits.length == 64, "Invalid scBits length"); // 512 bits = 64 bytes
        require(nextSc.length == 24624, "Invalid nextSc length"); // 513 * 48 bytes

        // Compute and validate period
        uint256 newPeriod = slot / (SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD);
        require(newPeriod == period + 1, "Period must be exactly period + 1");

        // Compute nextSyncCommitteeRoot using SSZ (for proof verification)
        bytes32 nextScRoot = _scRoot(nextSc);

        // Prepare public inputs for the verifier
        // input[0] = SyncCommitteePubKeysCommit (current sync committee)
        // input[1..32] = NextSyncCommitteeRoot (32 bytes)
        uint256[33] memory input;

        // input[0] is the current sync committee commitment (syncCommitteeHash)
        input[0] = uint256(scPubkeysHash);

        // input[1..32] are the 32 bytes of nextScRoot
        for (uint256 i = 0; i < 32; i++) {
            input[i + 1] = uint256(uint8(nextScRoot[i]));
        }

        // Call the verifier with [0,0] for commitments and commitmentPok
        uint256[2] memory commitments = [uint256(0), uint256(0)];
        uint256[2] memory commitmentPok = [uint256(0), uint256(0)];
        verifier.verifyProof(proof, commitments, commitmentPok, input);

        // If verification succeeds, compute and store Poseidon hash
        // Extract limbs from pubkeys (first 24576 bytes, excluding aggregate_pubkey)
        // Each pubkey (48 bytes) → extract limbs[4], limbs[5] (8 bytes each)
        // 512 pubkeys × 2 limbs = 1024 limbs
        bytes8[] memory limbs = new bytes8[](1024);
        for (uint256 i = 0; i < 512; i++) {
            uint256 offset = i * 48;
            bytes8 limb0;
            bytes8 limb1;
            assembly {
                // Extract limbs[4] (bytes 32-39 of the pubkey)
                let data0 := calldataload(add(nextSc.offset, add(offset, 32)))
                limb0 := shl(192, shr(192, data0))

                // Extract limbs[5] (bytes 40-47 of the pubkey)
                let data1 := calldataload(add(nextSc.offset, add(offset, 40)))
                limb1 := shl(192, shr(192, data1))
            }
            limbs[i * 2] = limb0;
            limbs[i * 2 + 1] = limb1;
        }

        // Compute Poseidon hash of pubkeys and update state
        scPubkeysHash = _pubKeysHash(limbs);
        period = newPeriod;
    }

    function _pubKeysHash(bytes8[] memory limbs) internal pure returns (bytes32) {
        // Streaming Poseidon hash (Merkle-Damgård construction)
        // state = Compress(state, data) for each data element
        // which is equivalent to: state = PoseidonT3.hash([state, data])

        uint256 state = 0; // Initial state

        console.log("limbs.length", limbs.length);

        for (uint256 i = 0; i < limbs.length; i++) {
            // Convert bytes8 to uint256
            uint256 data = uint256(uint64(limbs[i]));
            // Compress: state = hash(state, data)
            state = PoseidonT3.hash([state, data]);

            if(i<10) {
                console.logBytes8(limbs[i]);
            }
        }

        return bytes32(state);
    }

    function _scRoot(bytes memory syncCommitteeData) internal pure returns (bytes32) {
        // SSZ Merkleization for SyncCommittee Container:
        // struct SyncCommittee {
        //     pubkeys: Vector[BLSPubkey, 512]  // 512 * 48 = 24576 bytes
        //     aggregate_pubkey: BLSPubkey      // 48 bytes
        // }
        // Total: 24576 + 48 = 24624 bytes
        // Container HashTreeRoot = hash(pubkeysRoot, aggregatePubkeyRoot)

        require(syncCommitteeData.length == 24624, "Invalid sync committee data length");

        // Part 1: Compute pubkeys root (512 pubkeys, bytes 0-24575)
        bytes32[512] memory leaves;
        for (uint256 i = 0; i < 512; i++) {
            uint256 offset = i * 48;
            bytes32 chunk0;
            bytes32 chunk1;
            assembly {
                chunk0 := mload(add(add(syncCommitteeData, 32), offset))
                let data := mload(add(add(syncCommitteeData, 32), add(offset, 32)))
                chunk1 := and(data, 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000)
            }
            leaves[i] = sha256(abi.encodePacked(chunk0, chunk1));
        }

        // Build Merkle tree from 512 leaves
        bytes32[256] memory level1;
        for (uint256 i = 0; i < 256; i++) {
            level1[i] = sha256(abi.encodePacked(leaves[i * 2], leaves[i * 2 + 1]));
        }
        bytes32[128] memory level2;
        for (uint256 i = 0; i < 128; i++) {
            level2[i] = sha256(abi.encodePacked(level1[i * 2], level1[i * 2 + 1]));
        }
        bytes32[64] memory level3;
        for (uint256 i = 0; i < 64; i++) {
            level3[i] = sha256(abi.encodePacked(level2[i * 2], level2[i * 2 + 1]));
        }
        bytes32[32] memory level4;
        for (uint256 i = 0; i < 32; i++) {
            level4[i] = sha256(abi.encodePacked(level3[i * 2], level3[i * 2 + 1]));
        }
        bytes32[16] memory level5;
        for (uint256 i = 0; i < 16; i++) {
            level5[i] = sha256(abi.encodePacked(level4[i * 2], level4[i * 2 + 1]));
        }
        bytes32[8] memory level6;
        for (uint256 i = 0; i < 8; i++) {
            level6[i] = sha256(abi.encodePacked(level5[i * 2], level5[i * 2 + 1]));
        }
        bytes32[4] memory level7;
        for (uint256 i = 0; i < 4; i++) {
            level7[i] = sha256(abi.encodePacked(level6[i * 2], level6[i * 2 + 1]));
        }
        bytes32[2] memory level8;
        for (uint256 i = 0; i < 2; i++) {
            level8[i] = sha256(abi.encodePacked(level7[i * 2], level7[i * 2 + 1]));
        }
        bytes32 pubkeysRoot = sha256(abi.encodePacked(level8[0], level8[1]));

        // Part 2: Compute aggregate_pubkey root (48 bytes at offset 24576)
        bytes32 aggChunk0;
        bytes32 aggChunk1;
        assembly {
            aggChunk0 := mload(add(add(syncCommitteeData, 32), 24576))
            let data := mload(add(add(syncCommitteeData, 32), 24608))
            aggChunk1 := and(data, 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000)
        }
        bytes32 aggregatePubkeyRoot = sha256(abi.encodePacked(aggChunk0, aggChunk1));

        // Part 3: Container root = hash(pubkeysRoot, aggregatePubkeyRoot)
        return sha256(abi.encodePacked(pubkeysRoot, aggregatePubkeyRoot));
    }

    // Test function for _pubKeysHash
    function testPubKeysHash(bytes calldata pubKeys) public pure returns (bytes32) {
        require(pubKeys.length % 48 == 0, "pubKeys length must be multiple of 48");

        // Extract limbs from pubkeys
        // Each pubkey (48 bytes) → extract limbs[4], limbs[5] (8 bytes each)
        uint256 numPubkeys = pubKeys.length / 48;
        bytes8[] memory limbs = new bytes8[](numPubkeys * 2);
        for (uint256 i = 0; i < numPubkeys; i++) {
            uint256 offset = i * 48;
            bytes8 limb0;
            bytes8 limb1;
            assembly {
                // Extract limbs[0] (bytes 40-47 of the pubkey)
                let data0 := calldataload(add(pubKeys.offset, add(offset, 40)))
                limb0 := shl(192, shr(192, data0))

                // Extract limbs[1] (bytes 32-39 of the pubkey)
                let data1 := calldataload(add(pubKeys.offset, add(offset, 32)))
                limb1 := shl(192, shr(192, data1))
            }
            limbs[i * 2] = limb0;
            limbs[i * 2 + 1] = limb1;
        }

        return _pubKeysHash(limbs);
    }

    // Test function for _scRoot
    function testScRoot(bytes memory syncCommitteeData) public pure returns (bytes32) {
        return _scRoot(syncCommitteeData);
    }
}