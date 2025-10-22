const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ZKAsset", function () {
  let zkAsset;
  let verifier;
  let owner;
  let user1;
  let user2;

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();

    // Deploy PlonkVerifier
    const PlonkVerifier = await ethers.getContractFactory("PlonkVerifier");
    verifier = await PlonkVerifier.deploy();
    await verifier.deployed();

    // Deploy ZKAsset
    const ZKAsset = await ethers.getContractFactory("ZKAsset");
    zkAsset = await ZKAsset.deploy(verifier.address);
    await zkAsset.deployed();
  });

  describe("Deployment", function () {
    it("Should set the correct verifier", async function () {
      expect(await zkAsset.verifier()).to.equal(verifier.address);
    });

    it("Should initialize with empty tree", async function () {
      const [merkleRoot, leafCount] = await zkAsset.getTreeState();
      expect(leafCount).to.equal(0);
      expect(merkleRoot).to.not.equal(0);
    });

    it("Should have correct tree depth", async function () {
      expect(await zkAsset.TREE_DEPTH()).to.equal(5);
      expect(await zkAsset.MAX_LEAVES()).to.equal(32);
    });
  });

  describe("Deposits", function () {
    it("Should allow deposits of note commitments", async function () {
      const commitment = ethers.utils.randomBytes(32);
      const commitmentBigInt = ethers.BigNumber.from(commitment);

      await expect(zkAsset.deposit(commitmentBigInt))
        .to.emit(zkAsset, "NoteAdded")
        .withArgs(commitmentBigInt, 0);

      expect(await zkAsset.noteExists(commitmentBigInt)).to.be.true;

      const [merkleRoot, leafCount] = await zkAsset.getTreeState();
      expect(leafCount).to.equal(1);
    });

    it("Should reject duplicate commitments", async function () {
      const commitment = ethers.utils.randomBytes(32);
      const commitmentBigInt = ethers.BigNumber.from(commitment);

      await zkAsset.deposit(commitmentBigInt);

      await expect(zkAsset.deposit(commitmentBigInt))
        .to.be.revertedWithCustomError(zkAsset, "InvalidNoteCommitment");
    });

    it("Should update merkle tree correctly", async function () {
      const commitment1 = ethers.BigNumber.from(ethers.utils.randomBytes(32));
      const commitment2 = ethers.BigNumber.from(ethers.utils.randomBytes(32));

      const [initialRoot] = await zkAsset.getTreeState();

      await zkAsset.deposit(commitment1);
      const [rootAfterFirst] = await zkAsset.getTreeState();
      expect(rootAfterFirst).to.not.equal(initialRoot);

      await zkAsset.deposit(commitment2);
      const [rootAfterSecond] = await zkAsset.getTreeState();
      expect(rootAfterSecond).to.not.equal(rootAfterFirst);
    });
  });

  describe("Merkle Proofs", function () {
    it("Should generate correct merkle proofs", async function () {
      const commitment = ethers.BigNumber.from(ethers.utils.randomBytes(32));

      await zkAsset.deposit(commitment);

      const proof = await zkAsset.getMerkleProof(0);
      expect(proof.length).to.equal(6); // TREE_DEPTH + 1
      expect(proof[0]).to.equal(commitment); // First element should be the leaf
    });

    it("Should reject invalid leaf indices", async function () {
      await expect(zkAsset.getMerkleProof(0))
        .to.be.revertedWith("Invalid leaf index");
    });
  });

  describe("Nullifiers", function () {
    it("Should track nullifier usage", async function () {
      const nullifier = ethers.BigNumber.from(ethers.utils.randomBytes(32));

      expect(await zkAsset.isNullifierUsed(nullifier)).to.be.false;

      // We can't easily test the transfer function without a valid proof,
      // but we can test the nullifier tracking logic through other means
    });
  });

  describe("Access Control", function () {
    it("Should allow anyone to make deposits", async function () {
      const commitment = ethers.BigNumber.from(ethers.utils.randomBytes(32));

      await expect(zkAsset.connect(user1).deposit(commitment))
        .to.emit(zkAsset, "NoteAdded");
    });
  });

  describe("Edge Cases", function () {
    it("Should handle maximum tree capacity", async function () {
      const maxLeaves = await zkAsset.MAX_LEAVES();

      // Fill the tree to capacity
      for (let i = 0; i < maxLeaves; i++) {
        const commitment = ethers.BigNumber.from(ethers.utils.hexlify(ethers.utils.randomBytes(32)));
        await zkAsset.deposit(commitment);
      }

      const [, leafCount] = await zkAsset.getTreeState();
      expect(leafCount).to.equal(maxLeaves);

      // Next deposit should fail
      const commitment = ethers.BigNumber.from(ethers.utils.randomBytes(32));
      await expect(zkAsset.deposit(commitment))
        .to.be.revertedWithCustomError(zkAsset, "TreeIsFull");
    });

    it("Should handle zero commitments", async function () {
      await expect(zkAsset.deposit(0))
        .to.emit(zkAsset, "NoteAdded")
        .withArgs(0, 0);
    });
  });
});