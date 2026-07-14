// Multi-hop swap routing. Port of the browser extension's routing fallback
// (quantumswap-browser-extension src/bridge/handlers/chain.js): when no direct
// pair exists between the two tokens, a route is searched through intermediate
// hop candidates (wrapped Q + the recognized tokens), with at most
// SWAP_MAX_INTERMEDIATE_HOPS tokens between the from- and to-token.
import { loadQuantumCoin, loadQuantumSwap } from "./sdk";
import { SWAP_WQ_CONTRACT_ADDRESS, SWAP_FACTORY_CONTRACT_ADDRESS } from "./rpc";
import { searchSwapPath, SWAP_NO_ROUTE_ERROR } from "./swap-path-search";

export { SWAP_NO_ROUTE_ERROR };

// Recognized token contract addresses (Heisen, Y2Q). Duplicated from the
// renderer's src/lib/tokenfilter.ts because the main process is a separate
// TypeScript project; keep the two lists in sync.
export const RECOGNIZED_TOKEN_CONTRACT_ADDRESSES = [
    "0xe8ea8beb86e714ef2bde0afac17d6e45d1c35e48f312d6dc12c4fdb90d9e8a3d", // Heisen
    "0xa8036870874fbed790ed4d3bbd41b2f390b9858ff021f2993e90c6d1cbb167c7", // Y2Q
];

function swapHopCandidateAddresses(): string[] {
    return [SWAP_WQ_CONTRACT_ADDRESS, ...RECOGNIZED_TOKEN_CONTRACT_ADDRESSES];
}

// Route + symbol caches. Pairs rarely change, so a short TTL avoids re-querying
// the factory on every debounced quote / gas-estimate while a swap is being set up.
const SWAP_ROUTE_CACHE_TTL_MS = 60000;
const swapRouteCache = new Map<string, { path: string[] | null; at: number }>();
const swapPathSymbolCache = new Map<string, string>();

export function mapSwapTokenValue(value: string): string {
    return value === "Q" ? SWAP_WQ_CONTRACT_ADDRESS : value;
}

async function factoryPairExists(factory: any, tokenA: string, tokenB: string): Promise<boolean> {
    const { ZeroAddress } = loadQuantumCoin();
    const pairAddr = await factory.getPair(tokenA, tokenB);
    const pairAddrStr =
        typeof pairAddr === "string"
            ? pairAddr
            : pairAddr && pairAddr.toString
                ? pairAddr.toString()
                : String(pairAddr);
    const zeroAddr =
        ZeroAddress || "0x0000000000000000000000000000000000000000000000000000000000000000";
    return !!(pairAddrStr && pairAddrStr !== zeroAddr && pairAddrStr !== "0x" + "0".repeat(64));
}

// Find a router path from `fromAddrRaw` to `toAddrRaw`: the direct pair when it
// exists, otherwise the shortest route (BFS) through the hop candidates, limited
// to SWAP_MAX_INTERMEDIATE_HOPS intermediate tokens. Returns an array of
// checksummed addresses ([from, ...hops, to]) or null when no route exists.
export async function findSwapPath(
    provider: any,
    chainId: number,
    fromAddrRaw: string,
    toAddrRaw: string,
): Promise<string[] | null> {
    const { getAddress } = loadQuantumCoin();
    const { QuantumSwapV2Factory } = loadQuantumSwap();

    const fromAddr = getAddress(fromAddrRaw);
    const toAddr = getAddress(toAddrRaw);
    // The factory address is part of the key so a route cached for one pair set
    // is never served for another (mirrors the extension's per-release keying).
    const cacheKey =
        chainId +
        "|" +
        SWAP_FACTORY_CONTRACT_ADDRESS.toLowerCase() +
        "|" +
        fromAddr.toLowerCase() +
        "|" +
        toAddr.toLowerCase();
    const cached = swapRouteCache.get(cacheKey);
    if (cached && Date.now() - cached.at < SWAP_ROUTE_CACHE_TTL_MS) return cached.path;

    const factory = QuantumSwapV2Factory.connect(SWAP_FACTORY_CONTRACT_ADDRESS, provider);
    const seen = new Set([fromAddr.toLowerCase(), toAddr.toLowerCase()]);
    const hops: string[] = [];
    for (const h of swapHopCandidateAddresses()) {
        const addr = getAddress(h);
        if (seen.has(addr.toLowerCase())) continue;
        seen.add(addr.toLowerCase());
        hops.push(addr);
    }
    const nodes = [fromAddr, ...hops, toAddr];
    const path = await searchSwapPath(nodes, (a, b) => factoryPairExists(factory, a, b));

    if (swapRouteCache.size > 200) {
        swapRouteCache.delete(swapRouteCache.keys().next().value as string);
    }
    swapRouteCache.set(cacheKey, { path, at: Date.now() });
    return path;
}

// Resolve the router path for a swap between two UI token values ("Q" or a
// contract address). Throws when no route exists so callers surface the error.
export async function resolveSwapPath(
    provider: any,
    chainId: number,
    fromTokenValue: string,
    toTokenValue: string,
): Promise<string[]> {
    const path = await findSwapPath(
        provider,
        chainId,
        mapSwapTokenValue(fromTokenValue),
        mapSwapTokenValue(toTokenValue),
    );
    if (!path) throw new Error(SWAP_NO_ROUTE_ERROR);
    return path;
}

// On-chain symbol() for each path token, for the UI's route display. A failed
// lookup yields null for that entry (the UI falls back to the address). The raw
// symbol strings are untrusted RPC data: the UI must sanitize before rendering.
export async function getSwapPathSymbols(
    provider: any,
    chainId: number,
    path: string[],
): Promise<(string | null)[]> {
    const { IERC20 } = loadQuantumSwap();
    return Promise.all(
        path.map(async (addr) => {
            const key = chainId + "|" + addr.toLowerCase();
            const cachedSymbol = swapPathSymbolCache.get(key);
            if (cachedSymbol != null) return cachedSymbol;
            let symbol: string | null = null;
            try {
                const token: any = IERC20.connect(addr, provider);
                if (typeof token.symbol === "function") {
                    const s = await token.symbol();
                    if (typeof s === "string" && s.trim() !== "") symbol = s;
                }
            } catch {
                /* leave null */
            }
            // Cache only successful lookups: a transient RPC failure must not pin
            // the null (address-fallback) display for the rest of the session.
            if (symbol != null) swapPathSymbolCache.set(key, symbol);
            return symbol;
        }),
    );
}
