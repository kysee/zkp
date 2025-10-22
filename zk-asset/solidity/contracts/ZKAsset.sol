// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PlonkVerifier.sol";

/**
 * @title ZKAsset
 * @dev Private asset transfer system using zero-knowledge proofs
 * Features:
 * - Confidential transfers (hidden amounts, addresses)
 * - Double-spend prevention via nullifiers
 * - Note commitments for UTXO tracking
 * - Encrypted notes for recipient-only visibility
 */
contract ZKAsset {
    // Plonk verifier contract
    PlonkVerifier public immutable verifier;

    // Merkle tree for note commitments
    uint256 public constant TREE_DEPTH = 32;
    uint256 public constant MAX_LEAVES = 2**TREE_DEPTH;

    // State variables
    mapping(uint256 => bool) public nullifiers;
    mapping(uint256 => bool) public noteCommitments;
    uint256[] public merkleTree;
    uint256 public nextLeafIndex;
    uint256 public merkleRoot;

    // Events
    event Transfer(
        uint256 indexed nullifier,
        uint256 indexed newNoteCommitment,
        uint256 indexed changeNoteCommitment,
        bytes encryptedNote
    );

    event NoteAdded(uint256 indexed commitment, uint256 leafIndex);

    // Errors
    error InvalidProof();
    error NullifierAlreadyUsed();
    error InvalidNoteCommitment();
    error TreeIsFull();
    error InvalidMerkleRoot();

    constructor(address _verifier) {
        verifier = PlonkVerifier(_verifier);

        // Initialize merkle tree with empty leaves
        merkleTree = new uint256[](MAX_LEAVES * 2);
        nextLeafIndex = 0;

        // Calculate initial empty tree root
        _updateMerkleRoot();
    }

    /**
     * @dev Execute a private transfer
     * @param proof ZK proof data
     * @param publicInputs Public circuit inputs [merkleRoot, nullifier, newNoteCommitment, changeNoteCommitment]
     * @param encryptedNote Encrypted note for recipient
     */
    function transfer(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes calldata encryptedNote
    ) external {
        require(publicInputs.length == 4, "Invalid public inputs length");

        uint256 inputMerkleRoot = publicInputs[0];
        uint256 nullifier = publicInputs[1];
        uint256 newNoteCommitment = publicInputs[2];
        uint256 changeNoteCommitment = publicInputs[3];

        // Verify merkle root matches current state
        if (inputMerkleRoot != merkleRoot) {
            revert InvalidMerkleRoot();
        }

        // Check nullifier hasn't been used
        if (nullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        // Verify the ZK proof
        if (!verifier.verifyProof(proof, publicInputs)) {
            revert InvalidProof();
        }

        // Mark nullifier as used
        nullifiers[nullifier] = true;

        // Add new note commitment to tree
        if (newNoteCommitment != 0) {
            _addNoteCommitment(newNoteCommitment);
        }

        // Add change note commitment to tree (if non-zero)
        if (changeNoteCommitment != 0) {
            _addNoteCommitment(changeNoteCommitment);
        }

        emit Transfer(nullifier, newNoteCommitment, changeNoteCommitment, encryptedNote);
    }

    /**
     * @dev Add initial note commitment (for deposits)
     * @param commitment Note commitment hash
     */
    function deposit(uint256 commitment) external {
        _addNoteCommitment(commitment);
        emit NoteAdded(commitment, nextLeafIndex - 1);
    }

    /**
     * @dev Add note commitment to merkle tree
     */
    function _addNoteCommitment(uint256 commitment) internal {
        if (nextLeafIndex >= MAX_LEAVES) {
            revert TreeIsFull();
        }

        if (noteCommitments[commitment]) {
            revert InvalidNoteCommitment();
        }

        // Add to commitments set
        noteCommitments[commitment] = true;

        // Add to merkle tree
        merkleTree[MAX_LEAVES + nextLeafIndex] = commitment;
        nextLeafIndex++;

        // Update merkle root
        _updateMerkleRoot();
    }

    /**
     * @dev Update merkle tree root after adding leaves
     */
    function _updateMerkleRoot() internal {
        // Build tree bottom-up
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            uint256 levelSize = MAX_LEAVES >> level;
            uint256 levelOffset = levelSize;

            for (uint256 i = 0; i < levelSize / 2; i++) {
                uint256 left = merkleTree[levelOffset + 2 * i];
                uint256 right = merkleTree[levelOffset + 2 * i + 1];
                merkleTree[levelOffset / 2 + i] = _hash(left, right);
            }
        }

        merkleRoot = merkleTree[1];
    }

    /**
     * @dev Generate merkle proof for a given leaf index
     * @param leafIndex Index of the leaf
     * @return path Merkle path from leaf to root
     */
    function getMerkleProof(uint256 leafIndex) external view returns (uint256[] memory path) {
        require(leafIndex < nextLeafIndex, "Invalid leaf index");

        path = new uint256[](TREE_DEPTH + 1);
        path[0] = merkleTree[MAX_LEAVES + leafIndex]; // leaf value

        uint256 currentIndex = MAX_LEAVES + leafIndex;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            uint256 siblingIndex = currentIndex % 2 == 0 ? currentIndex + 1 : currentIndex - 1;
            path[i + 1] = merkleTree[siblingIndex];
            currentIndex = currentIndex / 2;
        }

        return path;
    }

    /**
     * @dev Hash function for merkle tree (MiMC hash)
     * Note: This is a simplified hash for demo purposes
     * In production, use proper MiMC implementation
     */
    function _hash(uint256 left, uint256 right) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(left, right))) % 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    }

    /**
     * @dev Get current merkle tree state
     */
    function getTreeState() external view returns (uint256 root, uint256 leafCount) {
        return (merkleRoot, nextLeafIndex);
    }

    /**
     * @dev Check if nullifier has been used
     */
    function isNullifierUsed(uint256 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /**
     * @dev Check if note commitment exists
     */
    function noteExists(uint256 commitment) external view returns (bool) {
        return noteCommitments[commitment];
    }
}