import * as os from "os";
import * as path from "path";

export const SWAP_WQ_CONTRACT_ADDRESS = "0x0E49c26cd1ca19bF8ddA2C8985B96783288458754757F4C9E00a5439A7291628";
export const SWAP_FACTORY_CONTRACT_ADDRESS = "0xbbF45a1B60044669793B444eD01Eb33e03Bb8cf3c5b6ae7887B218D05C5Cbf1d";
export const SWAP_ROUTER_V2_CONTRACT_ADDRESS = "0x41323EF72662185f44a03ea0ad8094a0C9e925aB1102679D8e957e838054aac5";

export function signingOverrides(wallet: any, data: any, base: Record<string, unknown>): Record<string, unknown> {
    const fullSign = data && data.advancedSigningEnabled === true;
    return { ...base, signingContext: wallet.getSigningContext(fullSign) };
}

export function sanitizeSwapError(err: unknown): string {
    const msg = (err && (err as any).message) ? (err as any).message : String(err);
    return String(msg).replace(/uniswap/gi, "").trim();
}

function expandTildeInIpcPath(p: unknown): string {
    const t = String(p).trim();
    if (t.startsWith("~/")) {
        return path.join(os.homedir(), t.slice(2));
    }
    if (t.startsWith("~\\")) {
        return path.join(os.homedir(), t.slice(2));
    }
    return t;
}

export function buildSwapRpcUrl(rpcEndpoint: unknown): string | null {
    if (!rpcEndpoint || typeof rpcEndpoint !== "string") return null;
    const s = rpcEndpoint.trim();
    if (s.startsWith("http://") || s.startsWith("https://")) return s;
    if (/^\/\/\.\/pipe\//i.test(s)) return s;
    if (/^\\\\\.\\pipe\\/i.test(s)) {
        return "//./pipe/" + s.replace(/^\\\\\.\\pipe\\/i, "").replace(/\\/g, "/");
    }
    if (s.startsWith("/") && !s.startsWith("//") && /\.ipc$/i.test(s)) return s;
    if (/\.ipc$/i.test(s) && (s.startsWith("~/") || s.startsWith("~\\") || /^~[^/\\]+[/\\]/.test(s))) return expandTildeInIpcPath(s);
    const isIpAddress = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(s);
    const isLocalhost = /^localhost(:\d+)?$/i.test(s);
    return (isIpAddress || isLocalhost ? "http://" : "https://") + s;
}

export function isIpcLikeRpc(rpcEndpoint: unknown): boolean {
    if (!rpcEndpoint || typeof rpcEndpoint !== "string") return false;
    const t = rpcEndpoint.trim();
    if (!t) return false;
    if (/^\/\/\.\/pipe\//i.test(t)) return true;
    if (/^\\\\\.\\pipe\\/i.test(t)) return true;
    if (!/\.ipc$/i.test(t)) return false;
    if (t.startsWith("/") && !t.startsWith("//")) return true;
    if (t.startsWith("~/") || t.startsWith("~\\")) return true;
    if (/^~[^/\\]+[/\\]/.test(t)) return true;
    return false;
}

export function toNodeIpcPath(rpcEndpoint: unknown): string {
    const t = expandTildeInIpcPath(String(rpcEndpoint).trim());
    if (process.platform === "win32" && /^\/\/\.\/pipe\//i.test(t)) {
        return "\\\\.\\pipe\\" + t.replace(/^\/\/\.\/pipe\//i, "").replace(/\//g, "\\");
    }
    return t;
}

/** Same endpoint string shape as createQuantumRpcProvider (IPC path vs HTTP URL). */
export function initRpcUrlForConfig(rpcEndpoint: unknown): string | null {
    if (rpcEndpoint == null || typeof rpcEndpoint !== "string" || !rpcEndpoint.trim()) {
        return null;
    }
    if (isIpcLikeRpc(rpcEndpoint)) {
        return toNodeIpcPath(rpcEndpoint);
    }
    return buildSwapRpcUrl(rpcEndpoint);
}

export function createQuantumRpcProvider(rpcEndpoint: unknown, chainId: number): any {
    if (rpcEndpoint == null || typeof rpcEndpoint !== "string" || !rpcEndpoint.trim()) return null;
    const { getProvider } = require("quantumcoin");
    const endpoint = isIpcLikeRpc(rpcEndpoint) ? toNodeIpcPath(rpcEndpoint) : buildSwapRpcUrl(rpcEndpoint);
    if (!endpoint) return null;
    const provider = getProvider(endpoint, chainId);
    if (provider && Number.isInteger(chainId)) {
        provider.chainId = chainId;
    }
    return provider;
}

function looksLikeLocalIpcRpc(rpcEndpoint: unknown): boolean {
    if (!rpcEndpoint || typeof rpcEndpoint !== "string") return false;
    const t = rpcEndpoint.trim();
    return /^\/\/\.\/pipe\//i.test(t) || /^\\\\\.\\pipe\\/i.test(t) || (/\.ipc$/i.test(t) && !/^https?:\/\//i.test(t));
}

/** Add short, actionable hints for common local IPC / socket failures (Windows EPERM, etc.). */
export function formatLocalRpcConnectionError(rpcEndpoint: unknown, err: any): string {
    let msg = (err && err.message) ? String(err.message) : String(err);
    if (err && err.error && err.error.message && !msg.includes(String(err.error.message))) {
        msg = msg + " " + String(err.error.message);
    }
    if (!looksLikeLocalIpcRpc(rpcEndpoint)) {
        return msg;
    }
    const lower = msg.toLowerCase();
    const code = err && (err.code || (err.error && err.error.code));
    if (lower.includes("eperm") || code === "EPERM") {
        return msg + "\n\nTip: EPERM = pipe access denied. Run Geth and the wallet as the same user and admin level, or use Geth HTTP in rpcEndpoint.";
    }
    if (lower.includes("eacces") || code === "EACCES") {
        return msg + "\n\nTip: Access denied. Same user/elevation as Geth, or HTTP rpcEndpoint.";
    }
    if (lower.includes("enoent") || lower.includes("econnrefused") || lower.includes("refused") || code === "ENOENT") {
        return msg + "\n\nTip: Pipe not available. Start Geth; check --ipcpath, or use HTTP rpcEndpoint.";
    }
    return msg;
}

/** Strip locale formatting (e.g. commas) so parseUnits gets a valid numeric string. */
export function normalizeAmountString(value: unknown): string {
    if (value == null) return "0";
    return String(value).replace(/,/g, "").trim() || "0";
}

/** Router compares deadline to block.timestamp; use chain time so local nodes do not hit UniswapV2Router: EXPIRED. */
export async function getSwapTxDeadline(provider: any, futureSeconds: number): Promise<bigint> {
    const sec = BigInt(Math.max(60, Math.min(86400, Number(futureSeconds) > 0 ? Number(futureSeconds) : 1200)));
    try {
        if (provider && typeof provider.getBlock === "function") {
            const block = await provider.getBlock("latest");
            if (block != null && block.timestamp != null) {
                const ts = typeof block.timestamp === "bigint" ? block.timestamp : BigInt(block.timestamp);
                return ts + sec;
            }
        }
    } catch {
        /* fall through */
    }
    return BigInt(Math.floor(Date.now() / 1000)) + sec;
}

export function formatSwapRouterRevertError(err: any): string {
    const msg = (err && err.message) ? String(err.message) : String(err);
    const lower = msg.toLowerCase();
    if (lower.includes("expired") && (lower.includes("uniswap") || lower.includes("router"))) {
        return msg + "\n\nTip: EXPIRED = swap deadline before chain time. Try again; sync PC clock or check node if it repeats.";
    }
    return msg;
}

export function base64ToBytes(base64: string): Uint8Array {
    const binString = atob(base64);
    return Uint8Array.from(binString, (m) => m.codePointAt(0) as number);
}

export function bytesToBase64(bytes: Uint8Array): string {
    const binString = Array.from(bytes, (byte) =>
        String.fromCodePoint(byte),
    ).join("");
    return btoa(binString);
}
