// Common gas configuration constants & helpers. 1:1 port of the gas section
// of the old src/js/app.js.
import { base64ToBytes } from "../lib/crypto";
import { estimateGas, estimateGasFee } from "../lib/bridge";
import { byId, GasState, networkStore, TxContext, walletStore } from "./state";
import { showGasConfigDialog } from "./dialog";
import { advancedSigningGetDefaultValue, offlineTxnSigningGetDefaultValue } from "./settings";
import { applySwapReleaseToPayload } from "./release";

export const SWAP_GAS_FEE_RATE = 1000 / 21000;

export const GAS_ESTIMATE_BUFFER_PERCENT = 10;
export const GAS_NO_BUFFER_PERCENT = 0;
export const GAS_ESTIMATE_DEBOUNCE_MS = 2000;
export const GAS_FEE_DECIMALS = 4;
export const GAS_FEE_UNIT_LABEL = "Q";
// Wallet key type is derived from the public key byte length and drives gas-price
// selection in provider.getFeeData(keyType, fullSign). 3 = HYBRIDEDMLDSASLHDSA, 5 = HYBRIDEDMLDSASLHDSA5.
export const WALLET_KEY_TYPE_3 = 3;
export const WALLET_KEY_TYPE_5 = 5;
export const PUBLIC_KEY_LENGTH_KEYTYPE3 = 1408;
export const PUBLIC_KEY_LENGTH_KEYTYPE5 = 2688;
export const DEFAULT_WALLET_KEY_TYPE = WALLET_KEY_TYPE_3;

// Derive the current wallet's key type from its public key (base64). The public key
// is held in memory after login (currentWallet.publicKey), so this needs no password.
export function getWalletKeyType(): number {
    try {
        const pubB64 = (walletStore.currentWallet && walletStore.currentWallet.publicKey) ? walletStore.currentWallet.publicKey : null;
        if (!pubB64) return DEFAULT_WALLET_KEY_TYPE;
        const bytes = base64ToBytes(pubB64);
        const len = (bytes && bytes.length) ? bytes.length : 0;
        if (len === PUBLIC_KEY_LENGTH_KEYTYPE5) return WALLET_KEY_TYPE_5;
        if (len === PUBLIC_KEY_LENGTH_KEYTYPE3) return WALLET_KEY_TYPE_3;
        return DEFAULT_WALLET_KEY_TYPE;
    } catch {
        return DEFAULT_WALLET_KEY_TYPE;
    }
}

export const currentGasConfig: GasState = { gasLimit: null, gasFee: null, overridden: false };
let gasEstimateTimerId: ReturnType<typeof setTimeout> | null = null;
let gasEstimateToken = 0;

// Format the gas fee as a number string with no trailing zeros (LSB only).
// Decimals are shown only when present: 110 -> "110", 0.5 -> "0.5", 0.0476 -> "0.0476".
export function formatGasFeeNumber(value: unknown): string {
    let n = parseFloat(String(value));
    if (isNaN(n)) n = 0;
    let s = n.toFixed(GAS_FEE_DECIMALS);
    if (s.indexOf(".") >= 0) {
        s = s.replace(/0+$/, "");
        if (s.slice(-1) === ".") s = s.slice(0, -1);
    }
    return s;
}

export function formatGasFeeQ(value: unknown): string {
    return formatGasFeeNumber(value) + " " + GAS_FEE_UNIT_LABEL;
}

export function setGasFeeLabel(labelId: string, feeValue: unknown): void {
    const el = byId(labelId);
    if (!el) return;
    if (feeValue == null || feeValue === "") {
        el.textContent = "";
        return;
    }
    el.textContent = formatGasFeeQ(feeValue);
}

export function setGasIconPulse(iconId: string, pulsing: boolean): void {
    const el = byId(iconId);
    if (!el) return;
    if (pulsing) {
        el.classList.add("gas-pulse");
    } else {
        el.classList.remove("gas-pulse");
    }
}

export function resetCurrentGasConfig(state?: GasState): void {
    const s = state || currentGasConfig;
    s.gasLimit = null;
    s.gasFee = null;
    s.overridden = false;
    if (gasEstimateTimerId) { clearTimeout(gasEstimateTimerId); gasEstimateTimerId = null; }
    gasEstimateToken++;
    s._token = gasEstimateToken;
}

// Compute the offline/default gas config from a hardcoded gas-limit constant.
export function applyOfflineGasConfig(defaultGasLimit: number, labelId: string | null, state?: GasState): void {
    const s = state || currentGasConfig;
    const gasLimit = defaultGasLimit;
    const gasFee = (gasLimit * SWAP_GAS_FEE_RATE);
    s.gasLimit = String(gasLimit);
    s.gasFee = String(gasFee);
    s.overridden = false;
    if (labelId) setGasFeeLabel(labelId, gasFee);
}

// Build the estimateGas IPC payload for a given tx context.
// `ctx` is provided by the calling screen and must include txKind + the relevant fields.
export function buildEstimateGasPayload(ctx: TxContext): Record<string, unknown> | null {
    if (!networkStore.currentBlockchainNetwork) return null;
    const payload: Record<string, unknown> = {
        rpcEndpoint: networkStore.currentBlockchainNetwork.rpcEndpoint,
        chainId: parseInt(String(networkStore.currentBlockchainNetwork.networkId), 10),
        txKind: ctx.txKind,
        fromAddress: walletStore.currentWalletAddress,
    };
    if (ctx.toAddress) payload.toAddress = ctx.toAddress;
    if (ctx.amount != null) payload.amount = ctx.amount;
    if (ctx.contractAddress) payload.contractAddress = ctx.contractAddress;
    if (ctx.fromDecimals != null) payload.fromDecimals = ctx.fromDecimals;
    if (ctx.fromTokenValue) payload.fromTokenValue = ctx.fromTokenValue;
    if (ctx.toTokenValue) payload.toTokenValue = ctx.toTokenValue;
    if (ctx.amountIn != null) payload.amountIn = ctx.amountIn;
    if (ctx.amountOut != null) payload.amountOut = ctx.amountOut;
    if (ctx.lastChanged) payload.lastChanged = ctx.lastChanged;
    if (ctx.slippagePercent != null) payload.slippagePercent = ctx.slippagePercent;
    if (ctx.recipientAddress) payload.recipientAddress = ctx.recipientAddress;
    if (ctx.methodArgs) payload.methodArgs = ctx.methodArgs;
    if (ctx.value != null) payload.value = ctx.value;
    if (ctx.bufferPercent != null) payload.bufferPercent = ctx.bufferPercent;
    // Liquidity / pools / token-creation fields (Settings -> Advanced).
    if (ctx.tokenAValue) payload.tokenAValue = ctx.tokenAValue;
    if (ctx.tokenBValue) payload.tokenBValue = ctx.tokenBValue;
    if (ctx.amountA != null) payload.amountA = ctx.amountA;
    if (ctx.amountB != null) payload.amountB = ctx.amountB;
    if (ctx.decimalsA != null) payload.decimalsA = ctx.decimalsA;
    if (ctx.decimalsB != null) payload.decimalsB = ctx.decimalsB;
    if (ctx.ownerAddress) payload.ownerAddress = ctx.ownerAddress;
    if (ctx.tokenAddress) payload.tokenAddress = ctx.tokenAddress;
    if (ctx.tokenAAddress) payload.tokenAAddress = ctx.tokenAAddress;
    if (ctx.tokenBAddress) payload.tokenBAddress = ctx.tokenBAddress;
    if (ctx.liquidityWei != null) payload.liquidityWei = ctx.liquidityWei;
    if (ctx.amountAMinWei != null) payload.amountAMinWei = ctx.amountAMinWei;
    if (ctx.amountBMinWei != null) payload.amountBMinWei = ctx.amountBMinWei;
    if (ctx.name != null) payload.name = ctx.name;
    if (ctx.symbol != null) payload.symbol = ctx.symbol;
    if (ctx.decimals != null) payload.decimals = ctx.decimals;
    if (ctx.totalSupply != null) payload.totalSupply = ctx.totalSupply;
    const releaseStampedKinds = ["swap", "approve", "approveToken", "addLiquidity", "removeLiquidity", "createPair"];
    if (releaseStampedKinds.indexOf(ctx.txKind) !== -1) {
        applySwapReleaseToPayload(payload);
    }
    return payload;
}

export type TxContextProvider = TxContext | null | (() => TxContext | null);

export interface PerTransactionGasEstimate {
    gasLimit: string;
    gasFee: string;
    feePerGas: number;
    usedFallback: boolean;
    error: string | null;
}

// Estimate one transaction against the current chain state. Compound flows
// call this only when a step becomes current, after prior receipts succeeded.
export async function estimateGasForContext(ctx: TxContext): Promise<PerTransactionGasEstimate> {
    const payload = buildEstimateGasPayload(ctx);
    if (!payload) throw new Error("Gas estimation is unavailable.");

    let usedFallback = false;
    let error: string | null = null;
    let gasLimit: string | null = null;
    try {
        const est = await estimateGas(payload);
        if (est && est.success && est.gasLimit) {
            gasLimit = String(est.gasLimit);
        } else {
            usedFallback = true;
            error = est && est.error ? String(est.error) : null;
        }
    } catch (err: any) {
        usedFallback = true;
        error = (err && err.message) ? String(err.message) : String(err);
    }

    if (gasLimit == null) {
        if (!ctx.defaultGasLimit) throw new Error(error || "Gas estimation failed.");
        gasLimit = String(ctx.defaultGasLimit);
    }

    const fullSign = await advancedSigningGetDefaultValue();
    const keyType = getWalletKeyType();
    let gasFee: string | null = null;
    try {
        const feeRes = await estimateGasFee({
            rpcEndpoint: networkStore.currentBlockchainNetwork!.rpcEndpoint,
            chainId: parseInt(String(networkStore.currentBlockchainNetwork!.networkId), 10),
            gasLimit,
            keyType,
            fullSign: fullSign === true,
        });
        if (feeRes && feeRes.success && feeRes.gasFeeEth != null) {
            gasFee = String(feeRes.gasFeeEth);
            if (feeRes.usedFallback === true) {
                usedFallback = true;
                if (feeRes.error) error = String(feeRes.error);
            }
        } else {
            usedFallback = true;
            if (feeRes && feeRes.error) error = String(feeRes.error);
        }
    } catch (err: any) {
        usedFallback = true;
        error = (err && err.message) ? String(err.message) : String(err);
    }

    if (gasFee == null) {
        gasFee = String(Number(gasLimit) * SWAP_GAS_FEE_RATE);
        usedFallback = true;
    }
    const limitNumber = Number(gasLimit);
    const feeNumber = Number(gasFee);
    return {
        gasLimit,
        gasFee,
        feePerGas: limitNumber > 0 && Number.isFinite(feeNumber) ? feeNumber / limitNumber : SWAP_GAS_FEE_RATE,
        usedFallback,
        error,
    };
}

// Schedule a debounced gas estimation. `ctxProvider` returns the tx context (or null to skip),
// `iconId`/`labelId` identify the UI elements. `state` is the gas-state object to update
// (defaults to the global currentGasConfig). Respects offline mode (no network lookup).
// `onRpcError` (optional) is invoked once if the network gas-price lookup fails (RPC error).
export function scheduleGasEstimation(ctxProvider: TxContextProvider, iconId: string, labelId: string | null, state?: GasState | null, onRpcError?: (msg: string | null) => void): void {
    const s = state || currentGasConfig;
    if (gasEstimateTimerId) { clearTimeout(gasEstimateTimerId); gasEstimateTimerId = null; }
    gasEstimateToken++;
    s._token = gasEstimateToken;
    if (!s.overridden) {
        setGasIconPulse(iconId, true);
        if (labelId) setGasFeeLabel(labelId, "");
    }
    gasEstimateTimerId = setTimeout(function () {
        gasEstimateTimerId = null;
        runGasEstimation(ctxProvider, iconId, labelId, state, onRpcError);
    }, GAS_ESTIMATE_DEBOUNCE_MS);
}

export async function runGasEstimation(ctxProvider: TxContextProvider, iconId: string, labelId: string | null, state?: GasState | null, onRpcError?: (msg: string | null) => void): Promise<void> {
    const s = state || currentGasConfig;
    const myToken = s._token;
    const ctx = (typeof ctxProvider === "function") ? ctxProvider() : ctxProvider;
    if (!ctx || !ctx.txKind || !networkStore.currentBlockchainNetwork) {
        if (labelId) setGasFeeLabel(labelId, "");
        setGasIconPulse(iconId, false);
        s.gasLimit = null;
        s.gasFee = null;
        s.overridden = false;
        return;
    }

    const offline = await offlineTxnSigningGetDefaultValue();
    if (offline === true) {
        // Offline: no network lookup. Use the hardcoded default for this tx kind.
        if (ctx.defaultGasLimit) {
            applyOfflineGasConfig(ctx.defaultGasLimit, labelId, state ?? undefined);
        } else {
            setGasIconPulse(iconId, false);
        }
        return;
    }

    if (s.overridden) {
        // User has manually overridden; keep their values until context actually changes.
        if (labelId) setGasFeeLabel(labelId, s.gasFee);
        setGasIconPulse(iconId, false);
        return;
    }

    setGasIconPulse(iconId, true);
    if (labelId) setGasFeeLabel(labelId, "");
    try {
        const result = await estimateGasForContext(ctx);
        if (myToken !== s._token) { setGasIconPulse(iconId, false); return; }
        if (!s.overridden) {
            s.gasLimit = result.gasLimit;
            s.gasFee = result.gasFee;
            s.overridden = false;
            if (labelId) setGasFeeLabel(labelId, s.gasFee);
        }
        setGasIconPulse(iconId, false);
        if (result.usedFallback && typeof onRpcError === "function") {
            onRpcError(result.error);
        }
    } catch (e: any) {
        if (myToken !== s._token) { setGasIconPulse(iconId, false); return; }
        s.gasLimit = null;
        s.gasFee = null;
        s.overridden = false;
        if (labelId) setGasFeeLabel(labelId, "");
        setGasIconPulse(iconId, false);
        if (typeof onRpcError === "function") {
            onRpcError((e && e.message) ? String(e.message) : String(e));
        }
    }
}

// Open the Gas config dialog prefilled with the current values; on OK, override.
// `ctxProvider` (optional) is used to gate the offline-default pre-apply: the default
// fee is only applied when the tx context is valid (inputs present), so no fee is
// shown before the required quantity/inputs have been entered.
export function onGasIconClick(labelId: string, state?: GasState | null, ctxProvider?: () => TxContext | null): boolean {
    const s = state || currentGasConfig;
    if (s.gasLimit == null && typeof ctxProvider === "function") {
        const ctx = ctxProvider();
        if (ctx && ctx.txKind && ctx.defaultGasLimit) {
            applyOfflineGasConfig(ctx.defaultGasLimit, labelId, state ?? undefined);
        }
    }
    showGasConfigDialog({
        gasLimit: s.gasLimit != null ? s.gasLimit : "",
        gasFee: s.gasFee != null ? formatGasFeeNumber(s.gasFee) : "",
        onOk: function (result) {
            // Invalidate any pending/in-flight estimation so its async result can't
            // overwrite this manual override (which would silently reset overridden
            // to false and submit the auto-estimated gas instead of the user's value).
            if (gasEstimateTimerId) { clearTimeout(gasEstimateTimerId); gasEstimateTimerId = null; }
            gasEstimateToken++;
            s._token = gasEstimateToken;
            s.gasLimit = String(result.gasLimit);
            s.gasFee = String(result.gasFee);
            s.overridden = true;
            if (labelId) setGasFeeLabel(labelId, s.gasFee);
        },
    });
    return false;
}

// Resolve the gas limit + fee to use for submission/review, falling back to defaults.
export function resolveGasForTx(defaultGasLimit: number, state?: GasState | null): { gasLimit: string; gasFee: string } {
    const s = state || currentGasConfig;
    if (s.gasLimit != null && s.gasLimit !== "") {
        const gl = parseInt(s.gasLimit, 10);
        if (!isNaN(gl) && gl > 0) {
            const fee = s.gasFee != null ? s.gasFee : (gl * SWAP_GAS_FEE_RATE);
            return { gasLimit: String(gl), gasFee: formatGasFeeQ(fee) };
        }
    }
    return {
        gasLimit: String(defaultGasLimit),
        gasFee: formatGasFeeQ(defaultGasLimit * SWAP_GAS_FEE_RATE),
    };
}

// Swap gas defaults (offline / network-failure fallbacks).
export const SWAP_DEFAULT_GAS = 200000;
export const APPROVE_DEFAULT_GAS = 84000;
