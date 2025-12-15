import { ethers, NonceManager } from "ethers";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import {loadProof, loadSyncCommittee, projectRoot, syncCommitteePubkeysToBytes, syncCommitteeToBytes} from "./utils.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  // Get network config from hardhat.config.ts
  const rpcUrl = "http://127.0.0.1:8545/";
  const privateKey = "0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e";

  // Create provider and wallet
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  const managedWallet = new NonceManager(wallet);

  console.log("Network URL:", rpcUrl);
  console.log("Using account:", wallet.address);

  // Load contract artifacts
  const scUpdateVerifierArtifact = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "../artifacts/contracts/ScUpdateVerifier.sol/ScUpdateVerifier.json"),
      "utf8"
    )
  );

  const lightClientArtifact = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "../artifacts/contracts/LightClient.sol/LightClient.json"),
      "utf8"
    )
  );

  // Deploy ScUpdateVerifier
  console.log("\n=== Deploying ScUpdateVerifier ===");
  const ScUpdateVerifierFactory = new ethers.ContractFactory(
    scUpdateVerifierArtifact.abi,
    scUpdateVerifierArtifact.bytecode,
      managedWallet
  );
  const scUpdateVerifier = await ScUpdateVerifierFactory.deploy();
  await scUpdateVerifier.waitForDeployment();
  const scUpdateVerifierAddress = await scUpdateVerifier.getAddress();
  console.log("ScUpdateVerifier deployed to:", scUpdateVerifierAddress);



  // Deploy LightClient
  const initialPeriod = BigInt(1104); // periods
  const initialScPubkeysHash = "0x8bd26c003d619dc6aa13e4c7b31d01910a87f43da84070e6cbdd4d45a91da3f3";

  console.log("\n=== Deploying LightClient ===");
  console.log("Initial period:", initialPeriod);
  console.log("Initial scPubkeysHash:", initialScPubkeysHash);
  console.log("ScUpdateVerifier address:", scUpdateVerifierAddress);

  const LightClientFactory = new ethers.ContractFactory(
    lightClientArtifact.abi,
    lightClientArtifact.bytecode,
      managedWallet
  );
  const lightClient: any = await LightClientFactory.deploy(
    initialPeriod,
    initialScPubkeysHash,
    scUpdateVerifierAddress
  );
  await lightClient.waitForDeployment();
  const lightClientAddress = await lightClient.getAddress();
  console.log("LightClient deployed to:", lightClientAddress);

  // Verify deployment
  console.log("\n=== Verifying LightClient Deployment ===");
  const period = await lightClient.period();
  const scPubkeysHash = await lightClient.scPubkeysHash();
  const verifierAddress = await lightClient.verifier();

  console.log("Stored period:", period);
  console.log("Stored scPubkeysHash:", scPubkeysHash);
  console.log("Stored verifier address:", verifierAddress);

// Test testScRoot
  const slot = 9052234;
  const nextSc = loadSyncCommittee(`${projectRoot()}/../data/lcupdate.json`);
  const szNextSc = syncCommitteeToBytes(nextSc);
  console.log("szNextSc.pubkes (+aggreagte):", szNextSc.length / 48);
    try {
        const estimatedGas = await lightClient.testScRoot.estimateGas(szNextSc, {gasLimit: 30000000});
        console.log("testScRoot - Estimated gas needed:", estimatedGas.toString());
        console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
    } catch (err) {
        console.error("estimateGas failed:", err);
    }

    const nextScRoot = await lightClient.testScRoot(szNextSc);
    console.log("testScRoot result:", nextScRoot);

    const proofData = loadProof(`${projectRoot()}/../data/proof.json`)
    try {
            const estimatedGas = await lightClient.updateSyncCommittee.estimateGas(
                proofData.proof, proofData.commitments, proofData.commitmentPok,
                slot, szNextSc,
                {gasLimit: 30000000});
            console.log("updateSyncCommitteeCompressed - Estimated gas needed:", estimatedGas.toString());
            console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
        } catch (err) {
            console.error("estimateGas failed:", err);
        }

  // const [compressedProof, compressedCommitments, compressedCommitmentPok] = await scUpdateVerifier.compressProof(proofData.proof, proofData.commitments, proofData.commitmentPok, {gasLimit: 30000000});
  //   console.log("\n=== Compressed Proof Data ===");
  //   console.log("compressedProof (uint256[4]):", compressedProof);
  //   console.log("compressedCommitments (uint256[1]):", compressedCommitments);
  //   console.log("compressedCommitmentPok (uint256):", compressedCommitmentPok);
  //
  //   // Convert Result objects to plain arrays (ethers.js Result is read-only)
  //   const compressedProofArray = [...compressedProof];
  //   const compressedCommitmentsArray = [...compressedCommitments];
  //
  //   // Debug: Verify parameters before calling
  //   console.log("\n=== Debug: Parameters for updateSyncCommitteeCompressed ===");
  //   console.log("slot:", slot);
  //   console.log("szNextSc length:", szNextSc.length, "bytes (expected: 24624)");
  //   console.log("Current period:", await lightClient.period());
  //   console.log("Expected newPeriod:", Math.floor(slot / (32 * 256)));
  //   console.log("compressedProofArray length:", compressedProofArray.length);
  //   console.log("compressedCommitmentsArray length:", compressedCommitmentsArray.length);
  //
  //
  //   try {
  //     const estimatedGas = await lightClient.updateSyncCommitteeCompressed.estimateGas(
  //         compressedProofArray, compressedCommitmentsArray, compressedCommitmentPok,
  //         slot, nextScRoot,
  //         {gasLimit: 30000000});
  //     console.log("updateSyncCommitteeCompressed - Estimated gas needed:", estimatedGas.toString());
  //     console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
  // } catch (err) {
  //     console.error("estimateGas failed:", err);
  // }

  // // Test helper functions
  // console.log("\n=== Testing Helper Functions ===");
  //
  // // Test testPubKeysHash
  // //const dummyPubKeys = "0x" + "00".repeat(24576);
  //   const currSc = loadSyncCommittee(`${projectRoot()}/../data/curr-sc.json`);
  //   const szCurrSc = syncCommitteePubkeysToBytes(currSc);
  //   console.log("szCurrSc:", szCurrSc.length);
  //   try {
  //       const estimatedGas = await lightClient.testPubKeysHash.estimateGas(szCurrSc, {gasLimit: 30000000});
  //       console.log("testPubKeysHash - Estimated gas needed:", estimatedGas.toString());
  //       console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
  //   } catch (err) {
  //       console.error("estimateGas failed:", err);
  //   }
  //   const pubKeysHash = await lightClient.testPubKeysHash(szCurrSc, {gasLimit: 30000000});
  //   // expected: 0x396609bcf49582474bf7c72c923ebc41f60cb28467fcdabe76c6728adba1c8e8
  //   console.log("testPubKeysHash result:", pubKeysHash);
  //

  console.log("\n=== Deployment Complete ===");
}


async function pubkeyHash() {
    
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });