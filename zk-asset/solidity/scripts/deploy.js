const { ethers } = require("hardhat");

async function main() {
  console.log("Deploying ZK Asset contracts...");

  // Get the deployer account
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString());

  // Deploy PlonkVerifier
  console.log("\n1. Deploying PlonkVerifier...");
  const PlonkVerifier = await ethers.getContractFactory("PlonkVerifier");
  const verifier = await PlonkVerifier.deploy();
  await verifier.deployed();
  console.log("✅ PlonkVerifier deployed to:", verifier.address);

  // Deploy ZKAsset
  console.log("\n2. Deploying ZKAsset...");
  const ZKAsset = await ethers.getContractFactory("ZKAsset");
  const zkAsset = await ZKAsset.deploy(verifier.address);
  await zkAsset.deployed();
  console.log("✅ ZKAsset deployed to:", zkAsset.address);

  // Get initial state
  const [merkleRoot, leafCount] = await zkAsset.getTreeState();
  console.log("\n📊 Initial State:");
  console.log("Merkle Root:", merkleRoot.toString());
  console.log("Leaf Count:", leafCount.toString());

  // Save deployment info
  const deploymentInfo = {
    network: hre.network.name,
    verifier: verifier.address,
    zkAsset: zkAsset.address,
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
  };

  console.log("\n🎉 Deployment completed successfully!");
  console.log("Deployment info:", JSON.stringify(deploymentInfo, null, 2));

  return deploymentInfo;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });