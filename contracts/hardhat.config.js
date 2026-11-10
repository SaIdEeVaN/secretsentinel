require("@nomicfoundation/hardhat-ethers");

// Sepolia is configured ONLY when both variables are present. The publisher key
// is read from the environment and must never be committed (PRD 15.4/20.4).
const { SEPOLIA_RPC_URL, ATTESTATION_PUBLISHER_KEY } = process.env;
const networks = {};
if (SEPOLIA_RPC_URL && ATTESTATION_PUBLISHER_KEY) {
  networks.sepolia = { url: SEPOLIA_RPC_URL, chainId: 11155111, accounts: [ATTESTATION_PUBLISHER_KEY] };
}

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } },
  paths: { sources: "./src", tests: "./test", cache: "./cache", artifacts: "./artifacts" },
  networks,
};
