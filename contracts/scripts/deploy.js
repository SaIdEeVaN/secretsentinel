// Deploy ScanRegistry to Sepolia (test funds only, dedicated publishing wallet).
//   SEPOLIA_RPC_URL=... ATTESTATION_PUBLISHER_KEY=... npm run deploy:sepolia
// The deploying key becomes owner AND initial publisher. Never reuse an
// application or treasury key here.
const { ethers, network } = require("hardhat");

async function main() {
  if (network.name !== "sepolia" && network.name !== "hardhat" && network.name !== "localhost") {
    throw new Error(`Refusing to deploy to ${network.name}; this demo targets Sepolia only.`);
  }
  const [deployer] = await ethers.getSigners();
  const Factory = await ethers.getContractFactory("ScanRegistry");
  const registry = await Factory.deploy(deployer.address);
  await registry.waitForDeployment();
  console.log(`ScanRegistry deployed on ${network.name} at ${await registry.getAddress()}`);
  console.log(`Owner/publisher: ${deployer.address}`);
  console.log("Set ATTESTATION_CONTRACT_ADDRESS and TRUSTED_ATTESTATION_SIGNERS accordingly.");
}

main().catch((err) => {
  console.error(err.message);
  process.exitCode = 1;
});
