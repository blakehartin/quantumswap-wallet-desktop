export function amountAfterSlippage(value: string, decimals: number, slippagePercent: number): string {
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) throw new Error("Invalid decimals");
    const normalized = String(value).replace(/,/g, "").trim();
    if (!/^\d+(\.\d+)?$/.test(normalized)) throw new Error("Invalid amount");
    const parts = normalized.split(".");
    const fraction = (parts[1] || "").slice(0, decimals).padEnd(decimals, "0");
    const units = BigInt((parts[0] || "0") + fraction);
    const bps = BigInt(Math.round(Math.max(0, Math.min(100, slippagePercent)) * 100));
    const minimum = units * (10000n - bps) / 10000n;
    if (decimals === 0) return minimum.toString();
    const padded = minimum.toString().padStart(decimals + 1, "0");
    const whole = padded.slice(0, -decimals);
    const frac = padded.slice(-decimals).replace(/0+$/, "");
    return frac ? whole + "." + frac : whole;
}

export function assignSequentialNonces<T>(steps: T[], startingNonce: number): Array<{ step: T; nonce: number }> {
    if (!Number.isInteger(startingNonce) || startingNonce < 0) throw new Error("Invalid starting nonce");
    return steps.map((step, index) => ({ step, nonce: startingNonce + index }));
}

export function nextOfflineNonce(currentNonce: number): string {
    if (!Number.isInteger(currentNonce) || currentNonce < 0) throw new Error("Invalid current nonce");
    return String(currentNonce + 1);
}

export function buildOfflineSwapPath(fromAddress: string, toAddress: string, intermediates: string[]): string[] {
    const path = [fromAddress, ...intermediates.map((value) => value.trim()).filter(Boolean), toAddress];
    if (path.length < 2 || path.length > 5) throw new Error("Invalid swap path");
    if (new Set(path.map((value) => value.toLowerCase())).size !== path.length) throw new Error("Swap path contains duplicate tokens");
    return path;
}
