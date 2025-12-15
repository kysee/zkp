import { ethers, NonceManager } from "ethers";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import {loadSyncCommittee, projectRoot, syncCommitteePubkeysToBytes, syncCommitteeToBytes} from "./utils.ts";

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

  const slot = 9052234;
  const nextSc = loadSyncCommittee(`${projectRoot()}/../data/lcupdate.json`);
  const szNextSc = syncCommitteeToBytes(nextSc);
  console.log("szNextSc.pubkes (+aggreagte):", szNextSc.length / 512);
  const scBits = "0xffffebf3dfffffffffdfffffffeffffffdfffffffcfbfffffbbfffdf7bdfffdffdfffff7ffffffbf9ff7fffdffeffe6fdeeb9ffffffffffffffffbdfffffffbf";
    const proof = "0x16977e86d20d1685ccb7e1f4324892f7cbb6dd9715ee0ac1a51b99ee4c24d8a30742c2d3e6f4f11f6e1f49fcc9e948abdf73c81284163b22d6a49bda63741e1a0a93dfa197e1163ef19dda3a5560f385bab010c8a87eca5e06b7d4bb4937dd391edcf98f60e82861f89e6a2698c3d0bd5f10aa13e31e34a86a6159a172d7280c221bf6cc0562d023051e42a067633070ba72142183dd4e0aff0224cc89491a14178eb71a1d6e4ba034d1ba62f1e23f5fbdee15adc9fa3402b25e38c50d5f73821335081612001ad846f070f57bd1d6d6aec8fa03efa15c8f194c6e375a9f53ec163e56a1ce14a101d5b3b3fb65a045e8e5b1d93a2041201657d68f2bddd357f90000000106027782790375e40bee2a3d4d5be8f3c5fb30285e8731b1152242954e0f07721f81ba59415d83d736557be85d0ba6c83d154d577a05c27b221e641903c167de029d7402cf3130e42664e9ff682680285bb225ef2681c5db508feb00586e44e12607df0d2628d617edb576b6499534c685812a551821bde196608ee24645c4bf";

    try {
      const estimatedGas = await lightClient.updateSyncCommittee.estimateGas(slot, scBits, szNextSc, proof, {gasLimit: 30000000});
      console.log("testPubKeysHash - Estimated gas needed:", estimatedGas.toString());
      console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
  } catch (err) {
      console.error("estimateGas failed:", err);
  }

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
  // // Test testScRoot
  //   const nextSc = loadSyncCommittee(`${projectRoot()}/../data/lcupdate.json`);
  //   const szNextSc = syncCommitteeToBytes(nextSc);
  //   console.log("szNextSc:", szNextSc.length);
  //   try {
  //       const estimatedGas = await lightClient.testScRoot.estimateGas(szNextSc, {gasLimit: 30000000});
  //       console.log("testScRoot - Estimated gas needed:", estimatedGas.toString());
  //       console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
  //   } catch (err) {
  //       console.error("estimateGas failed:", err);
  //   }
  //
  // const scRoot = await lightClient.testScRoot(szNextSc);
  // console.log("testScRoot result:", scRoot);

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