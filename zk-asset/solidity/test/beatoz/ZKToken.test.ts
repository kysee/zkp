import {deploy} from "../../scripts/beatoz/deploy";
import { expect } from "chai";
import { ethers } from "hardhat";
import {panicTxCommitResult, parseEvmCallError, parseTxCommitResult} from "../../scripts/beatoz/utils";

describe("ZKToken.sol@BEATOZ", function () {
    const chainAlias = "localnet0";
    let zkToken: any;
    let verifier: any;

    before(async function () {
        verifier = await deploy(chainAlias, "PlonkVerifier").catch(error => {
            console.error("PlonkVerifier deployment failed:", error);
            process.exit(1);
        });

        zkToken = await deploy(chainAlias, "ZKToken", [verifier.address]).catch(error => {
            console.error("PlonkVerifier deployment failed:", error);
            process.exit(1);
        });
        // console.log(`${verifier.address}`, "PlonkVerifier");
        // console.log(`${zkToken.address}`, "ZKToken");
    });

    describe("Deployment@BEATOZ", function () {
        it("Should set the correct verifier", async function () {
            const r = await zkToken.verifier();
            expect((await zkToken.verifier()).toLowerCase()).to.equal(verifier.address.toLowerCase());
        });

        it("Should initialize with empty tree", async function () {
            const [merkleRoot, leafCount] = await zkToken.getTreeState();
            expect(leafCount).to.equal(0);
            expect(merkleRoot).to.not.equal(0);
        });

        it("Should have correct tree depth", async function () {
            expect(await zkToken.TREE_DEPTH()).to.equal(5);
            expect(await zkToken.MAX_LEAVES()).to.equal(32);
        });
    });

    describe("Deposits", function () {
        const commitment0 = ethers.randomBytes(32);
        const commitmentBigInt0 = ethers.toBigInt(commitment0);

        it("Should allow deposits of note commitments", async function () {

            //await expect( zkToken.deposit(commitmentBigInt))
            //   .to.emit(zkToken, "NoteAdded")
            //   .withArgs(commitmentBigInt, 0);
            const resp = await zkToken.deposit(commitmentBigInt0);
            expect(parseTxCommitResult(resp)).to.be.null;

            expect(await zkToken.noteExists(commitmentBigInt0)).to.be.true;

            const [merkleRoot, leafCount] = await zkToken.getTreeState();
            expect(leafCount).to.equal(1);
        });

        it("Should reject duplicate commitments", async function () {
            // await expect(zkToken.deposit(commitmentBigInt))
            // .to.be.revertedWithCustomError(zkToken, "InvalidNoteCommitment");

            const resp = await zkToken.deposit(commitmentBigInt0);
            expect(parseTxCommitResult(resp)).to.not.null;
        });

        it("Should update merkle tree correctly", async function () {
          const commitment1 = ethers.toBigInt(ethers.randomBytes(32));
          const commitment2 = ethers.toBigInt(ethers.randomBytes(32));

          const [initialRoot] = await zkToken.getTreeState();

          const resp0 = await zkToken.deposit(commitment1);
          expect(parseTxCommitResult(resp0)).to.be.null;

          const [rootAfterFirst] = await zkToken.getTreeState();
          expect(rootAfterFirst).to.not.equal(initialRoot);

          const resp1 = await zkToken.deposit(commitment2);
          expect(parseTxCommitResult(resp1)).to.be.null;

          const [rootAfterSecond] = await zkToken.getTreeState();
          expect(rootAfterSecond).not.to.be.equal(rootAfterFirst);
        });
    });


    describe("Merkle Proofs", function () {
      it("Should generate correct merkle proofs", async function () {
        const commitment1 = ethers.toBigInt(ethers.randomBytes(32));

        const resp = await zkToken.deposit(commitment1);
        expect(parseTxCommitResult(resp)).to.be.null;

        const [merkleRoot, leafCount] = await zkToken.getTreeState();
        const proof = await zkToken.getMerkleProof(Number(leafCount) - 1);
        expect(proof.length).to.equal(6); // TREE_DEPTH + 1
        expect(proof[0]).to.equal(commitment1); // First element should be the leaf
      });

      it("Should reject invalid leaf indices", async function () {
          const [merkleRoot, leafCount] = await zkToken.getTreeState();
          const resp = await zkToken.getMerkleProof(Number(leafCount));
          expect(parseEvmCallError(resp, zkToken.web3)).includes("Invalid leaf index");
      });
    });

    describe("Nullifiers", function () {
      it("Should track nullifier usage", async function () {
        const nullifier = ethers.toBigInt(ethers.randomBytes(32));

        expect(await zkToken.isNullifierUsed(nullifier)).to.be.false;

        // We can't easily test the transfer function without a valid proof,
        // but we can test the nullifier tracking logic through other means
      });
    });

    // describe("Access Control", function () {
    //   it("Should allow anyone to make deposits", async function () {
    //     const commitment = ethers.toBigInt(ethers.randomBytes(32));
    //
    //     await expect(zkToken.connect(user1).deposit(commitment))
    //       .to.emit(zkToken, "NoteAdded");
    //   });
    // });

    // describe("Edge Cases", function () {
    //   it("Should handle maximum tree capacity", async function () {
    //     const maxLeaves = await zkAsset.MAX_LEAVES();
    //
    //     // Fill the tree to capacity
    //     for (let i = 0; i < maxLeaves; i++) {
    //       const commitment = ethers.BigNumber.from(ethers.utils.hexlify(ethers.utils.randomBytes(32)));
    //       await zkAsset.deposit(commitment);
    //     }
    //
    //     const [, leafCount] = await zkAsset.getTreeState();
    //     expect(leafCount).to.equal(maxLeaves);
    //
    //     // Next deposit should fail
    //     const commitment = ethers.BigNumber.from(ethers.utils.randomBytes(32));
    //     await expect(zkAsset.deposit(commitment))
    //       .to.be.revertedWithCustomError(zkAsset, "TreeIsFull");
    //   });
    //
    //   it("Should handle zero commitments", async function () {
    //     await expect(zkAsset.deposit(0))
    //       .to.emit(zkAsset, "NoteAdded")
    //       .withArgs(0, 0);
    //   });
    // });
});