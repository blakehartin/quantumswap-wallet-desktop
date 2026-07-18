import { ipcMain } from "electron";
import { loadQuantumCoin, loadQuantumCoinConfig, loadQuantumSwap } from "../sdk";
import { buildAddLiquidityCall, buildDeployTokenTx, buildRemoveLiquidityCall, parseDeployTokenInputs } from "../liquidity-tx";
import { createQuantumRpcProvider, resolveSwapReleaseAddresses, signingOverrides } from "../rpc";

type OfflineStepKind = "approve" | "swap" | "createPair" | "deployToken" | "addLiquidity" | "removeLiquidity";

interface OfflineStep {
    kind: OfflineStepKind;
    label: string;
    gasLimit: number;
    data: any;
}

export function registerOfflineSigningHandlers(): void {
    ipcMain.handle("OfflinePrepareSigning", async (_event, payload) => {
        try {
            const chainId = Number(payload.chainId);
            const provider = createQuantumRpcProvider(payload.rpcEndpoint, chainId);
            if (!provider) throw new Error("RPC unavailable");
            const nonce = await provider.getTransactionCount(payload.ownerAddress, "pending");
            const block = await provider.getBlock("latest");
            return {
                success: true,
                nonce: Number(nonce),
                chainTimestamp: block && block.timestamp != null ? Number(block.timestamp) : null,
                error: null,
            };
        } catch (err: any) {
            return { success: false, nonce: null, chainTimestamp: null, error: err?.message || String(err) };
        }
    });
    ipcMain.handle("OfflineSignTransactionBundle", async (_event, payload) => {
        try {
            const { Initialize } = loadQuantumCoinConfig();
            const { Wallet, getAddress, getCreateAddress, parseUnits, MaxUint256 } = loadQuantumCoin();
            const { IERC20, QuantumSwapV2Router02, QuantumSwapV2Factory } = loadQuantumSwap();
            const chainId = Number(payload.chainId);
            const startingNonce = Number(payload.startingNonce);
            const steps = payload.steps as OfflineStep[];
            if (!Number.isInteger(chainId)) throw new Error("Invalid chain ID");
            if (!Number.isInteger(startingNonce) || startingNonce < 0) throw new Error("Invalid starting nonce");
            if (!payload.privateKey || !payload.publicKey) throw new Error("Wallet keys required");
            if (!Array.isArray(steps) || steps.length < 1 || steps.length > 10) throw new Error("Invalid transaction steps");

            await Initialize(null);
            const wallet = Wallet.fromKeys(
                Buffer.from(payload.privateKey, "base64"),
                Buffer.from(payload.publicKey, "base64"),
            );
            const release = resolveSwapReleaseAddresses(payload);
            const signed: Array<{ label: string; nonce: number; txData: string; contractAddress?: string }> = [];

            for (let index = 0; index < steps.length; index++) {
                const step = steps[index];
                const nonce = startingNonce + index;
                const gasLimit = Number(step.gasLimit);
                if (!Number.isInteger(gasLimit) || gasLimit <= 0) throw new Error("Invalid gas limit");
                let tx: any;

                if (step.kind === "approve") {
                    const token = IERC20.connect(getAddress(step.data.tokenAddress), wallet);
                    const spender = getAddress(step.data.spender || release.router);
                    const amount = step.data.amount == null ? MaxUint256 : BigInt(String(step.data.amount));
                    tx = await token.populateTransaction.approve(spender, amount, signingOverrides(wallet, payload, { gasLimit }));
                } else if (step.kind === "swap") {
                    const router = QuantumSwapV2Router02.connect(release.router, wallet);
                    const path = (step.data.path as string[]).map((address) => getAddress(address));
                    if (path.length < 2 || path.length > 5) throw new Error("Invalid swap path");
                    tx = await router.populateTransaction.swapExactTokensForTokens(
                        parseUnits(String(step.data.amountIn), Number(step.data.fromDecimals)),
                        parseUnits(String(step.data.amountOutMin), Number(step.data.toDecimals)),
                        path,
                        getAddress(step.data.recipientAddress),
                        BigInt(String(step.data.deadline)),
                        signingOverrides(wallet, payload, { gasLimit }),
                    );
                } else if (step.kind === "createPair") {
                    const factory = QuantumSwapV2Factory.connect(release.factory, wallet);
                    tx = await factory.populateTransaction.createPair(
                        getAddress(step.data.tokenAAddress),
                        getAddress(step.data.tokenBAddress),
                        signingOverrides(wallet, payload, { gasLimit }),
                    );
                } else if (step.kind === "deployToken") {
                    tx = buildDeployTokenTx(parseDeployTokenInputs(step.data), wallet);
                } else if (step.kind === "addLiquidity") {
                    const router: any = QuantumSwapV2Router02.connect(release.router, wallet);
                    const call = await buildAddLiquidityCall(step.data, release, null);
                    const overrides = signingOverrides(wallet, payload, call.value > 0n ? { gasLimit, value: call.value } : { gasLimit });
                    tx = await router.populateTransaction[call.method](...call.args, overrides);
                } else if (step.kind === "removeLiquidity") {
                    const router: any = QuantumSwapV2Router02.connect(release.router, wallet);
                    const call = await buildRemoveLiquidityCall(step.data, release, null);
                    tx = await router.populateTransaction[call.method](
                        ...call.args,
                        signingOverrides(wallet, payload, { gasLimit }),
                    );
                } else {
                    throw new Error("Unsupported offline transaction kind");
                }

                const txData = await wallet.signTransaction(signingOverrides(wallet, payload, {
                    ...tx,
                    nonce,
                    chainId,
                    gasLimit,
                }));
                const entry: { label: string; nonce: number; txData: string; contractAddress?: string } = {
                    label: String(step.label || step.kind), nonce, txData: String(txData),
                };
                if (step.kind === "deployToken") {
                    entry.contractAddress = getCreateAddress({ from: wallet.address, nonce });
                }
                signed.push(entry);
            }
            return { success: true, transactions: signed, error: null };
        } catch (err: any) {
            return {
                success: false,
                transactions: null,
                error: err && err.message ? String(err.message) : String(err),
            };
        }
    });
}
