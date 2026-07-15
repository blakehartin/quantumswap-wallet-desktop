import { ipcMain } from "electron";
import { loadQuantumCoin, loadQuantumCoinConfig, loadQuantumSwap } from "../sdk";
import {
    createQuantumRpcProvider,
    initRpcUrlForConfig,
    resolveSwapReleaseAddresses,
    getSwapTxDeadline,
    normalizeAmountString,
} from "../rpc";
import { STAKING_CONTRACT_ADDRESS, STAKING_ABI_JSON, STAKING_ALLOWED_METHODS, prepareStakingMethodArgs } from "../stakingAbi";
import { mapSwapTokenValue, resolveSwapPath } from "../swap-routing";

const GAS_ESTIMATE_BUFFER_PERCENT = 10;
const WEI_PER_ETH = 1000000000000000000n;
const GAS_FEE_FALLBACK_RATE_NUM = 1000 / 21000; // current default rate, used only when network lookup fails
const DEFAULT_WALLET_KEY_TYPE = 3; // keyType 3 (HYBRIDEDMLDSASLHDSA); 5 = HYBRIDEDMLDSASLHDSA5

function toBigInt(value: unknown): bigint | null {
    if (typeof value === "bigint") return value;
    if (typeof value === "number") return BigInt(Math.trunc(value));
    const s = String(value);
    if (s.startsWith("0x") || s.startsWith("0X")) {
        try { return BigInt(s); } catch { return null; }
    }
    try { return BigInt(s); } catch { return null; }
}

// Resolve the current gas price (wei) from the provider. QuantumCoin's getFeeData is
// a local computation: provider.getFeeData(keyType, fullSign) -> qcsdk.getGasPrice(keyType, fullSign).
// keyType (3 or 5) is derived from the wallet's public key length and drives gas-price
// selection; fullSign applies only to keyType 3. Falls back to the fixed default rate
// only when the lookup fails or no keyType is available.
async function resolveGasPriceWei(provider: any, keyType: unknown, fullSign: boolean): Promise<{ gasPriceWei: bigint | null; usedFallback: boolean }> {
    if (provider && typeof provider.getFeeData === "function") {
        const kt = Number.isInteger(keyType) ? (keyType as number) : DEFAULT_WALLET_KEY_TYPE;
        try {
            const fd = await provider.getFeeData(kt, fullSign === true);
            if (fd && fd.gasPrice != null) {
                const gp = toBigInt(fd.gasPrice);
                if (gp != null) return { gasPriceWei: gp, usedFallback: false };
            }
        } catch { /* fall through to fallback */ }
    }
    return { gasPriceWei: null, usedFallback: true };
}

function weiToEthString(weiBigInt: bigint | null): string {
    if (weiBigInt == null) return "0";
    const scaled = (weiBigInt * 1000000n) / WEI_PER_ETH; // coins * 1e6
    const num = Number(scaled) / 1000000;
    return String(num);
}

function applyGasBuffer(gasLimitBi: unknown, percent: number | null): bigint | null {
    const base = toBigInt(gasLimitBi);
    if (base == null) return null;
    const pct = (percent == null) ? GAS_ESTIMATE_BUFFER_PERCENT : percent;
    return (base * (100n + BigInt(pct))) / 100n;
}

// Build the unsigned tx request (with `from`) for a given transaction kind, for estimateGas.
async function buildEstimateGasTx(data: any, provider: any): Promise<Record<string, unknown>> {
    const { Initialize, Config } = loadQuantumCoinConfig();
    const { parseUnits, getAddress, Contract } = loadQuantumCoin();
    const { QuantumSwapV2Router02, IERC20 } = loadQuantumSwap();

    const chainId = Number(data.chainId);
    await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
    const fromAddress = data.fromAddress || data.recipientAddress || null;
    const txKind = data.txKind;

    if (txKind === "sendCoin") {
        const valueWei = parseUnits(normalizeAmountString(data.amount), 18);
        return { to: getAddress(data.toAddress), value: valueWei, from: getAddress(fromAddress) };
    }

    if (txKind === "sendToken") {
        const decimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
        const amountWei = parseUnits(normalizeAmountString(data.amount), decimals);
        const token = IERC20.connect(getAddress(data.contractAddress), provider);
        const tx = await token.populateTransaction.transfer(getAddress(data.toAddress), amountWei);
        return { ...tx, from: getAddress(fromAddress) };
    }

    if (txKind === "approve") {
        const release = resolveSwapReleaseAddresses(data);
        const tokenAddr = mapSwapTokenValue(data.fromTokenValue, release);
        const spenderAddr = release.router;
        const decimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
        const amountWei = parseUnits(normalizeAmountString(data.amount), decimals);
        const token = IERC20.connect(getAddress(tokenAddr), provider);
        const tx = await token.populateTransaction.approve(getAddress(spenderAddr), amountWei);
        return { ...tx, from: getAddress(fromAddress) };
    }

    if (txKind === "swap") {
        const release = resolveSwapReleaseAddresses(data);
        const router = QuantumSwapV2Router02.connect(release.router, provider);
        const path = await resolveSwapPath(provider, chainId, data.fromTokenValue, data.toTokenValue, release);
        const fromDecimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
        const toDecimals = typeof data.toDecimals === "number" ? data.toDecimals : 18;
        const toAddress = data.recipientAddress || data.toAddress;
        const deadline = await getSwapTxDeadline(provider, 1200);
        const lastChanged = data.lastChanged === "to" ? "to" : "from";
        const slippagePercent = Math.max(0, Math.min(100, Number(data.slippagePercent) || 1));
        let amountInWei, amountOutMinWei;
        if (lastChanged === "to") {
            const amountOutWei = parseUnits(String(data.amountOut), toDecimals);
            const amountsIn = await router.getAmountsIn(amountOutWei, path);
            amountInWei = Array.isArray(amountsIn) ? amountsIn[0] : amountsIn;
            amountOutMinWei = (amountOutWei * BigInt(100 - slippagePercent)) / 100n;
        } else {
            amountInWei = parseUnits(String(data.amountIn), fromDecimals);
            const amountsOut = await router.getAmountsOut(amountInWei, path);
            const expectedAmountOutWei = Array.isArray(amountsOut) ? amountsOut[amountsOut.length - 1] : amountsOut;
            amountOutMinWei = (expectedAmountOutWei * BigInt(100 - slippagePercent)) / 100n;
        }
        const tx = await router.populateTransaction.swapExactTokensForTokens(
            amountInWei, amountOutMinWei, path, getAddress(toAddress), deadline
        );
        return { ...tx, from: getAddress(toAddress) };
    }

    // Staking contract methods
    if (STAKING_ALLOWED_METHODS && STAKING_ALLOWED_METHODS.includes(txKind)) {
        const contract = new Contract(STAKING_CONTRACT_ADDRESS, STAKING_ABI_JSON, provider);
        const methodArgs = prepareStakingMethodArgs(STAKING_ABI_JSON, txKind, data.methodArgs || []);
        // populateTransaction is declared as {} and filled from the ABI at runtime.
        const populate = contract.populateTransaction as Record<string, (...args: unknown[]) => Promise<object>>;
        const tx = await populate[txKind](...methodArgs);
        const out: Record<string, unknown> = { ...tx, from: getAddress(fromAddress) };
        if (data.value && data.value !== "0" && data.value !== "0.0") {
            out.value = parseUnits(normalizeAmountString(data.value), 18);
        }
        return out;
    }

    throw new Error("Unsupported txKind for estimateGas: " + txKind);
}

export function registerGasHandlers(): void {
    ipcMain.handle("estimateGas", async (_event, data) => {
        try {
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, gasLimit: null, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, gasLimit: null, error: "Invalid RPC endpoint" };

            const tx = await buildEstimateGasTx(data, provider);
            const estimated = await provider.estimateGas(tx);
            const bp = Number.isInteger(data.bufferPercent) ? data.bufferPercent : GAS_ESTIMATE_BUFFER_PERCENT;
            const buffered = (bp > 0) ? applyGasBuffer(estimated, bp) : estimated;
            if (buffered == null) return { success: false, gasLimit: null, error: "estimateGas returned no value" };
            return { success: true, gasLimit: buffered.toString(), error: null };
        } catch (err: any) {
            return { success: false, gasLimit: null, error: (err && err.message) ? err.message : String(err) };
        }
    });

    ipcMain.handle("estimateGasFee", async (_event, data) => {
        try {
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, gasFeeEth: null, gasPriceWei: null, usedFallback: true, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, gasFeeEth: null, gasPriceWei: null, usedFallback: true, error: "Invalid RPC endpoint" };

            const gasLimitBi = toBigInt(data.gasLimit);
            const resolved = await resolveGasPriceWei(provider, data.keyType, data.fullSign === true);
            if (resolved.usedFallback || resolved.gasPriceWei == null) {
                const fallbackFee = gasLimitBi != null ? (Number(gasLimitBi) * GAS_FEE_FALLBACK_RATE_NUM) : 0;
                return { success: true, gasFeeEth: String(fallbackFee), gasPriceWei: null, usedFallback: true, error: null };
            }
            const totalWei = (gasLimitBi != null ? gasLimitBi : 0n) * resolved.gasPriceWei;
            return { success: true, gasFeeEth: weiToEthString(totalWei), gasPriceWei: resolved.gasPriceWei.toString(), usedFallback: false, error: null };
        } catch (err: any) {
            const gasLimitBi = toBigInt(data.gasLimit);
            const fallbackFee = gasLimitBi != null ? (Number(gasLimitBi) * GAS_FEE_FALLBACK_RATE_NUM) : 0;
            return { success: false, gasFeeEth: String(fallbackFee), gasPriceWei: null, usedFallback: true, error: (err && err.message) ? err.message : String(err) };
        }
    });
}
