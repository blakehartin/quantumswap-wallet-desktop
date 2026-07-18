// Shared builders for the liquidity / pools / token-creation transactions.
// Used by both the submit handlers (electron/ipc/liquidity.ts) and gas
// estimation (electron/ipc/gas.ts) so the estimated tx always matches the
// submitted one. Ported from the quantumswap-web-app's addLiquidity.ts /
// removeLiquidity.ts payload construction.
import { loadQuantumCoin } from "./sdk";
import { SwapReleaseAddresses, getSwapTxDeadline, normalizeAmountString } from "./rpc";
import { mapSwapTokenValue } from "./swap-routing";
import { CREATED_TOKEN_ABI, CREATED_TOKEN_BYTECODE } from "./created-token";

export const LIQUIDITY_DEADLINE_SECONDS = 1200;

// Slippage tolerance in basis points on top of an exact amount (same math as
// the web app's minWithSlippage: percent -> bps, integer arithmetic).
export function minWeiWithSlippage(amount: bigint, slippagePercent: number): bigint {
    const bps = BigInt(Math.round(Math.max(0, Math.min(100, Number(slippagePercent) || 0)) * 100));
    if (bps <= 0n) return amount;
    return (amount * (10000n - bps)) / 10000n;
}

export function asBigInt(value: unknown): bigint {
    if (typeof value === "bigint") return value;
    if (typeof value === "number") return BigInt(Math.trunc(value));
    return BigInt(String(value));
}

export interface LiquidityRouterCall {
    method: string;
    args: unknown[];
    value: bigint;
}

// addLiquidity / addLiquidityETH arguments from an add-liquidity payload:
// { tokenAValue, tokenBValue ("Q" for native), amountA, amountB (human
// strings), decimalsA, decimalsB, slippagePercent, ownerAddress }.
// When one side is native Q the router's ETH variant is used with the native
// amount as tx value; the ERC20 side keeps its own decimals.
export async function buildAddLiquidityCall(data: any, release: SwapReleaseAddresses, provider: any): Promise<LiquidityRouterCall> {
    const { parseUnits, getAddress } = loadQuantumCoin();

    const decimalsA = typeof data.decimalsA === "number" ? data.decimalsA : 18;
    const decimalsB = typeof data.decimalsB === "number" ? data.decimalsB : 18;
    const amountAWei = parseUnits(normalizeAmountString(data.amountA), decimalsA);
    const amountBWei = parseUnits(normalizeAmountString(data.amountB), decimalsB);
    const slippagePercent = Number(data.slippagePercent);
    const amountAMinWei = minWeiWithSlippage(amountAWei, slippagePercent);
    const amountBMinWei = minWeiWithSlippage(amountBWei, slippagePercent);
    const to = getAddress(String(data.ownerAddress));
    const deadline = data.deadline != null
        ? asBigInt(data.deadline)
        : await getSwapTxDeadline(provider, LIQUIDITY_DEADLINE_SECONDS);

    const aIsNative = data.tokenAValue === "Q";
    const bIsNative = data.tokenBValue === "Q";
    if (aIsNative && bIsNative) throw new Error("Both sides cannot be the native coin");

    if (aIsNative || bIsNative) {
        const tokenValue = aIsNative ? data.tokenBValue : data.tokenAValue;
        const tokenAmount = aIsNative ? amountBWei : amountAWei;
        const tokenAmountMin = aIsNative ? amountBMinWei : amountAMinWei;
        const nativeAmount = aIsNative ? amountAWei : amountBWei;
        const nativeAmountMin = aIsNative ? amountAMinWei : amountBMinWei;
        return {
            method: "addLiquidityETH",
            args: [getAddress(String(tokenValue)), tokenAmount, tokenAmountMin, nativeAmountMin, to, deadline],
            value: nativeAmount,
        };
    }

    return {
        method: "addLiquidity",
        args: [
            getAddress(mapSwapTokenValue(String(data.tokenAValue), release)),
            getAddress(mapSwapTokenValue(String(data.tokenBValue), release)),
            amountAWei,
            amountBWei,
            amountAMinWei,
            amountBMinWei,
            to,
            deadline,
        ],
        value: 0n,
    };
}

// removeLiquidity / removeLiquidityETH arguments from a remove payload:
// { tokenAAddress, tokenBAddress (actual pair token addresses; one may be the
// release WQ), liquidityWei, amountAMinWei, amountBMinWei (wei strings computed
// by the renderer from the position share + slippage), ownerAddress }.
// A WQ side is paid out as native Q via the ETH variant, like the web app.
export async function buildRemoveLiquidityCall(data: any, release: SwapReleaseAddresses, provider: any): Promise<LiquidityRouterCall> {
    const { getAddress } = loadQuantumCoin();

    const tokenA = getAddress(String(data.tokenAAddress));
    const tokenB = getAddress(String(data.tokenBAddress));
    const liquidity = asBigInt(data.liquidityWei);
    const amountAMin = asBigInt(data.amountAMinWei);
    const amountBMin = asBigInt(data.amountBMinWei);
    const to = getAddress(String(data.ownerAddress));
    const deadline = data.deadline != null
        ? asBigInt(data.deadline)
        : await getSwapTxDeadline(provider, LIQUIDITY_DEADLINE_SECONDS);

    const wqLower = release.wq.toLowerCase();
    const aIsWq = tokenA.toLowerCase() === wqLower;
    const bIsWq = tokenB.toLowerCase() === wqLower;

    if (aIsWq || bIsWq) {
        const token = aIsWq ? tokenB : tokenA;
        const tokenMin = aIsWq ? amountBMin : amountAMin;
        const ethMin = aIsWq ? amountAMin : amountBMin;
        return { method: "removeLiquidityETH", args: [token, liquidity, tokenMin, ethMin, to, deadline], value: 0n };
    }

    return { method: "removeLiquidity", args: [tokenA, tokenB, liquidity, amountAMin, amountBMin, to, deadline], value: 0n };
}

export interface DeployTokenInputs {
    name: string;
    symbol: string;
    decimals: number;
    totalSupplyBase: bigint;
}

export function parseDeployTokenInputs(data: any): DeployTokenInputs {
    const { parseUnits } = loadQuantumCoin();
    const name = String(data.name ?? "").trim();
    const symbol = String(data.symbol ?? "").trim();
    const decimals = Number(data.decimals);
    if (name.length < 1 || name.length > 48) throw new Error("Invalid token name");
    if (!/^[A-Za-z0-9]{1,16}$/.test(symbol)) throw new Error("Invalid token symbol");
    if (!Number.isInteger(decimals) || decimals < 1 || decimals > 18) throw new Error("Invalid token decimals");
    const totalSupplyBase = parseUnits(normalizeAmountString(data.totalSupply), decimals);
    if (totalSupplyBase <= 0n) throw new Error("Invalid token total supply");
    return { name, symbol, decimals, totalSupplyBase };
}

// Unsigned deploy tx ({ to: null, data, value }) for the CreatedToken
// contract, via the SDK's ContractFactory encoding (requires Initialize()).
export function buildDeployTokenTx(inputs: DeployTokenInputs, signer: any): Record<string, unknown> {
    const { ContractFactory } = loadQuantumCoin();
    const factory = new ContractFactory(CREATED_TOKEN_ABI, CREATED_TOKEN_BYTECODE, signer);
    const tx = factory.getDeployTransaction(inputs.name, inputs.symbol, inputs.decimals, inputs.totalSupplyBase);
    return { ...tx };
}
