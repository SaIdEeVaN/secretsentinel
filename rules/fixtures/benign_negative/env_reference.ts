// BENIGN FIXTURE: keys are read from the environment, never hardcoded.
import { Wallet, JsonRpcProvider } from "ethers";

const provider = new JsonRpcProvider(process.env.RPC_URL);
export const wallet = new Wallet(process.env.PRIVATE_KEY!, provider);
export const accounts = [process.env.DEPLOYER_PRIVATE_KEY];
