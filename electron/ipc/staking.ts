import { ipcMain } from "electron";
import {
    createQuantumRpcProvider,
    initRpcUrlForConfig,
    normalizeAmountString,
    signingOverrides,
} from "../rpc";
import { STAKING_CONTRACT_ADDRESS, STAKING_ABI_JSON, STAKING_ALLOWED_METHODS, prepareStakingMethodArgs } from "../stakingAbi";

export function registerStakingHandlers(): void {
    ipcMain.handle("StakingContractSubmit", async (_event, data) => {
        try {
            const { Initialize, Config } = require("quantumcoin/config");
            const { Wallet, Contract, parseUnits } = require("quantumcoin");

            if (!data.method || !STAKING_ALLOWED_METHODS.includes(data.method)) return { success: false, txHash: null, error: "Invalid staking method" };
            if (!data.privateKey || !data.publicKey) return { success: false, txHash: null, error: "Wallet keys required" };
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, txHash: null, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, txHash: null, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const privBytes = Buffer.from(data.privateKey, "base64");
            const pubBytes = Buffer.from(data.publicKey, "base64");
            const wallet = Wallet.fromKeys(privBytes, pubBytes, provider);

            const contract = new Contract(STAKING_CONTRACT_ADDRESS, STAKING_ABI_JSON, wallet);
            const methodArgs = prepareStakingMethodArgs(STAKING_ABI_JSON, data.method, data.methodArgs);
            const gasLimit = Number(data.gasLimit) || 250000;
            const overrides: Record<string, unknown> = signingOverrides(wallet, data, { gasLimit });
            if (data.value && data.value !== "0" && data.value !== "0.0") {
                overrides.value = parseUnits(normalizeAmountString(data.value), 18);
            }
            methodArgs.push(overrides);

            const tx = await contract[data.method](...methodArgs);
            return { success: true, txHash: tx.hash, error: null };
        } catch (err: any) {
            return { success: false, txHash: null, error: (err && err.message) ? err.message : String(err) };
        }
    });

    ipcMain.handle("StakingContractOfflineSign", async (_event, data) => {
        try {
            const { Initialize } = require("quantumcoin/config");
            const { Wallet, Contract, parseUnits } = require("quantumcoin");

            if (!data.method || !STAKING_ALLOWED_METHODS.includes(data.method)) return { success: false, txData: null, error: "Invalid staking method" };
            if (!data.privateKey || !data.publicKey) return { success: false, txData: null, error: "Wallet keys required" };
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, txData: null, error: "Invalid chain ID" };
            const nonce = Number(data.nonce);
            if (!Number.isInteger(nonce) || nonce < 0) return { success: false, txData: null, error: "Invalid nonce" };

            await Initialize(null);
            const privBytes = Buffer.from(data.privateKey, "base64");
            const pubBytes = Buffer.from(data.publicKey, "base64");
            const wallet = Wallet.fromKeys(privBytes, pubBytes);

            const contract = new Contract(STAKING_CONTRACT_ADDRESS, STAKING_ABI_JSON, wallet);
            const methodArgs = prepareStakingMethodArgs(STAKING_ABI_JSON, data.method, data.methodArgs);
            const gasLimit = Number(data.gasLimit) || 250000;
            const overrides: Record<string, unknown> = signingOverrides(wallet, data, { gasLimit });
            if (data.value && data.value !== "0" && data.value !== "0.0") {
                overrides.value = parseUnits(normalizeAmountString(data.value), 18);
            }
            methodArgs.push(overrides);

            const txReq = await contract.populateTransaction[data.method](...methodArgs);
            const txData = await wallet.signTransaction(signingOverrides(wallet, data, { ...txReq, nonce: nonce, chainId: chainId }));
            return { success: true, txData: txData, error: null };
        } catch (err: any) {
            return { success: false, txData: null, error: (err && err.message) ? err.message : String(err) };
        }
    });
}
