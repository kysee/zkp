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
  const initialPeriod = BigInt(1000);
  const initialScPubkeysHash = "0x0000000000000000000000000000000000000000000000000000000000000001";

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

  // Test helper functions
  console.log("\n=== Testing Helper Functions ===");

  // Test testPubKeysHash
  //const dummyPubKeys = "0x" + "00".repeat(24576);
    const currSc = loadSyncCommittee(`${projectRoot()}/../data/curr-sc.json`);
    const szCurrSc = syncCommitteePubkeysToBytes(currSc);
    console.log("szCurrSc:", szCurrSc.length);
    try {
        const estimatedGas = await lightClient.testPubKeysHash.estimateGas(szCurrSc, {gasLimit: 30000000});
        console.log("testPubKeysHash - Estimated gas needed:", estimatedGas.toString());
        console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
    } catch (err) {
        console.error("estimateGas failed:", err);
    }
    const pubKeysHash = await lightClient.testPubKeysHash(szCurrSc, {gasLimit: 30000000});
    // expected: 0x396609bcf49582474bf7c72c923ebc41f60cb28467fcdabe76c6728adba1c8e8
    console.log("testPubKeysHash result:", pubKeysHash);

  // Test testScRoot
    const nextSc = loadSyncCommittee(`${projectRoot()}/../data/lcupdate.json`);
    const szNextSc = syncCommitteeToBytes(nextSc);
    console.log("szNextSc:", szNextSc.length);
    try {
        const estimatedGas = await lightClient.testScRoot.estimateGas(szNextSc, {gasLimit: 30000000});
        console.log("testScRoot - Estimated gas needed:", estimatedGas.toString());
        console.log("In millions:", (Number(estimatedGas) / 1_000_000).toFixed(2), "M");
    } catch (err) {
        console.error("estimateGas failed:", err);
    }

  const scRoot = await lightClient.testScRoot(szNextSc);
  console.log("testScRoot result:", scRoot);

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