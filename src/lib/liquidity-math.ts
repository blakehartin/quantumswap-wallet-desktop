// Pure bigint math for the liquidity screens: base-unit parsing/formatting
// (the renderer has no parseUnits), the constant-product proportional quote,
// slippage minimums, and LP position estimates. Ported from the
// quantumswap-web-app's src/lib/quoteMath.ts. No I/O - fully unit-testable.

/**
 * Parse a human amount string ("1.5", "1,234.56") into base units.
 * Throws on malformed input or more fraction digits than `decimals`.
 */
export function parseBaseUnits(value: string, decimals: number): bigint {
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
        throw new Error("parseBaseUnits invalid decimals");
    }
    const cleaned = String(value ?? "").replace(/,/g, "").trim();
    if (!/^\d+(\.\d*)?$|^\.\d+$/.test(cleaned)) {
        throw new Error("parseBaseUnits invalid amount");
    }
    const [wholeRaw, fractionRaw = ""] = cleaned.split(".");
    const whole = wholeRaw === "" ? "0" : wholeRaw;
    if (fractionRaw.length > decimals) {
        throw new Error("parseBaseUnits too many decimal places");
    }
    const fraction = fractionRaw.padEnd(decimals, "0");
    return BigInt(whole) * 10n ** BigInt(decimals) + (fraction === "" ? 0n : BigInt(fraction));
}

/**
 * Format base units as a human string, trimming trailing zeros and capping
 * the fraction at `maxFractionDigits` (truncation, not rounding).
 */
export function formatBaseUnits(value: bigint, decimals: number, maxFractionDigits: number = 6): string {
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
        throw new Error("formatBaseUnits invalid decimals");
    }
    const negative = value < 0n;
    const abs = negative ? -value : value;
    const base = 10n ** BigInt(decimals);
    const whole = abs / base;
    let fraction = (abs % base).toString().padStart(decimals, "0");
    if (fraction.length > maxFractionDigits) fraction = fraction.slice(0, maxFractionDigits);
    fraction = fraction.replace(/0+$/, "");
    const result = fraction === "" ? whole.toString() : whole.toString() + "." + fraction;
    return negative ? "-" + result : result;
}

/** Proportional quote (no fee): amountB for amountA at the current ratio. */
export function quote(amountA: bigint, reserveA: bigint, reserveB: bigint): bigint {
    if (amountA <= 0n || reserveA <= 0n || reserveB <= 0n) return 0n;
    return (amountA * reserveB) / reserveA;
}

/**
 * Apply slippage tolerance to compute a minimum-received amount.
 * slippagePercent e.g. 0.5 tolerates 0.5%. Basis points keep it in integers.
 */
export function minWithSlippage(amount: bigint, slippagePercent: number): bigint {
    const bps = BigInt(Math.round(Math.max(0, Math.min(100, Number(slippagePercent) || 0)) * 100));
    if (bps <= 0n) return amount;
    return (amount * (10000n - bps)) / 10000n;
}

/** Underlying token amount a LP balance is entitled to (pro-rata reserves). */
export function positionUnderlying(lpBalance: bigint, reserve: bigint, totalSupply: bigint): bigint {
    if (lpBalance <= 0n || reserve <= 0n || totalSupply <= 0n) return 0n;
    return (lpBalance * reserve) / totalSupply;
}

/** Pool share (percent, 0..100) of an LP balance. */
export function poolSharePercent(lpBalance: bigint, totalSupply: bigint): number {
    if (lpBalance <= 0n || totalSupply <= 0n) return 0;
    const bps = (lpBalance * 1000000n) / totalSupply;
    return Number(bps) / 10000;
}

/** Whole-percent slice (1..100) of an amount, for the remove-liquidity slider. */
export function percentOfAmount(amount: bigint, percent: number): bigint {
    const p = BigInt(Math.max(0, Math.min(100, Math.round(Number(percent) || 0))));
    if (p <= 0n || amount <= 0n) return 0n;
    return (amount * p) / 100n;
}

/**
 * Estimated pool share (percent) after adding `amountA` to a pool with
 * `reserveA` / `totalSupply` (web-app share estimate: minted = amountA *
 * totalSupply / reserveA, share = minted / (totalSupply + minted)).
 */
export function estimatedShareAfterAdd(amountA: bigint, reserveA: bigint, totalSupply: bigint): number {
    if (amountA <= 0n) return 0;
    if (reserveA <= 0n || totalSupply <= 0n) return 100;
    const minted = (amountA * totalSupply) / reserveA;
    return poolSharePercent(minted, totalSupply + minted);
}
