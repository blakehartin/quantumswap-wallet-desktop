// IPC handlers for the Tokens / Liquidity / Pools screens: pool discovery
// (factory walk), user LP positions, pair info for ratio autofill, token/LP
// allowance + approval toward the router, add/remove liquidity, pair creation
// and CreatedToken deployment. Ported from the quantumswap-web-app views
// (poolExplorer / positions / addLiquidity / removeLiquidity / createPair /
// createToken), adapted to the desktop's local-signing model.
import { ipcMain } from "electron";
import { loadQuantumCoin, loadQuantumCoinConfig, loadQuantumSwap } from "../sdk";
import {
    createQuantumRpcProvider,
    initRpcUrlForConfig,
    resolveSwapReleaseAddresses,
    sanitizeSwapError,
    formatSwapRouterRevertError,
    signingOverrides,
} from "../rpc";
import { mapSwapTokenValue } from "../swap-routing";
import {
    asBigInt,
    buildAddLiquidityCall,
    buildRemoveLiquidityCall,
    buildDeployTokenTx,
    parseDeployTokenInputs,
} from "../liquidity-tx";

// Factory walks are capped like the web app's pool explorer (limit 200).
const MAX_FACTORY_PAIRS = 200;

// symbol()/decimals() rarely change; cache per chain+address for the session.
const tokenMetaCache = new Map<string, { symbol: string | null; decimals: number }>();

async function getTokenMeta(provider: any, chainId: number, address: string): Promise<{ symbol: string | null; decimals: number }> {
    const key = chainId + "|" + address.toLowerCase();
    const cached = tokenMetaCache.get(key);
    if (cached) return cached;
    const { IERC20 } = loadQuantumSwap();
    const token: any = IERC20.connect(address, provider);
    let symbol: string | null = null;
    let decimals = 18;
    try {
        const s = await token.symbol();
        if (typeof s === "string" && s.trim() !== "") symbol = s;
    } catch { /* leave null; UI falls back to the address */ }
    try {
        const d = await token.decimals();
        const n = Number(d);
        if (Number.isInteger(n) && n >= 0 && n <= 36) decimals = n;
    } catch { /* default 18 */ }
    const meta = { symbol, decimals };
    // Cache only when the symbol resolved so a transient RPC failure does not
    // pin the address-fallback display for the whole session.
    if (symbol != null) tokenMetaCache.set(key, meta);
    return meta;
}

async function listFactoryPairAddresses(provider: any, factoryAddress: string): Promise<string[]> {
    const { QuantumSwapV2Factory } = loadQuantumSwap();
    const factory = QuantumSwapV2Factory.connect(factoryAddress, provider);
    const lenRaw = await factory.allPairsLength();
    const len = Math.min(Number(asBigInt(lenRaw)), MAX_FACTORY_PAIRS);
    const addrs: string[] = [];
    for (let i = 0; i < len; i++) {
        addrs.push(String(await factory.allPairs(i)));
    }
    return addrs;
}

interface PairSnapshot {
    pairAddress: string;
    token0: string;
    token1: string;
    symbol0: string | null;
    symbol1: string | null;
    decimals0: number;
    decimals1: number;
    reserve0: string;
    reserve1: string;
    totalSupply: string;
}

async function readPairSnapshot(provider: any, chainId: number, pairAddress: string): Promise<PairSnapshot> {
    const { QuantumSwapV2Pair } = loadQuantumSwap();
    const pair = QuantumSwapV2Pair.connect(pairAddress, provider);
    const [token0Raw, token1Raw, reservesRaw, totalSupplyRaw] = await Promise.all([
        pair.token0(),
        pair.token1(),
        pair.getReserves(),
        pair.totalSupply(),
    ]);
    const token0 = String(token0Raw);
    const token1 = String(token1Raw);
    const [meta0, meta1] = await Promise.all([
        getTokenMeta(provider, chainId, token0),
        getTokenMeta(provider, chainId, token1),
    ]);
    const reserves = reservesRaw as unknown as [unknown, unknown, unknown];
    return {
        pairAddress,
        token0,
        token1,
        symbol0: meta0.symbol,
        symbol1: meta1.symbol,
        decimals0: meta0.decimals,
        decimals1: meta1.decimals,
        reserve0: asBigInt(reserves[0]).toString(),
        reserve1: asBigInt(reserves[1]).toString(),
        totalSupply: asBigInt(totalSupplyRaw).toString(),
    };
}

function isZeroPairAddress(addr: unknown): boolean {
    const s = typeof addr === "string" ? addr : String(addr ?? "");
    if (!s || !s.startsWith("0x")) return true;
    return /^0x0+$/.test(s);
}

export function registerLiquidityHandlers(): void {
    ipcMain.handle("LiquidityListPools", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, pools: null, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, pools: null, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const pairAddresses = await listFactoryPairAddresses(provider, release.factory);
            const pools = await Promise.all(pairAddresses.map((addr) => readPairSnapshot(provider, chainId, addr)));
            return { success: true, pools, error: null };
        } catch (err) {
            return { success: false, pools: null, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("LiquidityListPositions", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { getAddress } = loadQuantumCoin();
            const { QuantumSwapV2Pair } = loadQuantumSwap();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, positions: null, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, positions: null, error: "Invalid RPC endpoint" };
            if (!data.ownerAddress) return { success: false, positions: null, error: "Owner address required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const owner = getAddress(String(data.ownerAddress));
            const pairAddresses = await listFactoryPairAddresses(provider, release.factory);

            const positions = (await Promise.all(pairAddresses.map(async (addr) => {
                const pair = QuantumSwapV2Pair.connect(addr, provider);
                const lpBalance = asBigInt(await pair.balanceOf(owner));
                if (lpBalance <= 0n) return null;
                const snapshot = await readPairSnapshot(provider, chainId, addr);
                return { ...snapshot, lpBalance: lpBalance.toString() };
            }))).filter((p) => p != null);
            return { success: true, positions, error: null };
        } catch (err) {
            return { success: false, positions: null, error: sanitizeSwapError(err) };
        }
    });

    // Pair lookup for two UI token values ("Q" or a contract address): used by
    // the add-liquidity ratio autofill and the create-pair existence check.
    ipcMain.handle("LiquidityGetPairInfo", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { getAddress } = loadQuantumCoin();
            const { QuantumSwapV2Factory } = loadQuantumSwap();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, exists: false, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, exists: false, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const tokenAAddress = getAddress(mapSwapTokenValue(String(data.tokenAValue), release));
            const tokenBAddress = getAddress(mapSwapTokenValue(String(data.tokenBValue), release));
            if (tokenAAddress.toLowerCase() === tokenBAddress.toLowerCase()) {
                return { success: false, exists: false, error: "Identical tokens" };
            }

            const factory = QuantumSwapV2Factory.connect(release.factory, provider);
            const pairAddr = await factory.getPair(tokenAAddress, tokenBAddress);
            if (isZeroPairAddress(pairAddr)) {
                return { success: true, exists: false, tokenAAddress, tokenBAddress, pair: null, lpBalance: null, error: null };
            }

            const snapshot = await readPairSnapshot(provider, chainId, String(pairAddr));
            let lpBalance: string | null = null;
            if (data.ownerAddress) {
                const { QuantumSwapV2Pair } = loadQuantumSwap();
                const pair = QuantumSwapV2Pair.connect(String(pairAddr), provider);
                lpBalance = asBigInt(await pair.balanceOf(getAddress(String(data.ownerAddress)))).toString();
            }
            return { success: true, exists: true, tokenAAddress, tokenBAddress, pair: snapshot, lpBalance, error: null };
        } catch (err) {
            return { success: false, exists: false, error: sanitizeSwapError(err) };
        }
    });

    // Allowance of an arbitrary token (ERC20 side or LP pair token) toward the
    // active release's router. requiredAmountWei is a base-units string.
    ipcMain.handle("LiquidityCheckAllowance", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { getAddress } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, sufficient: false, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, sufficient: false, error: "Invalid RPC endpoint" };
            if (!data.ownerAddress) return { success: false, sufficient: false, error: "Owner address required" };
            if (!data.tokenAddress) return { success: false, sufficient: false, error: "Token address required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const requiredWei = asBigInt(data.requiredAmountWei ?? 0);
            const token: any = IERC20.connect(getAddress(String(data.tokenAddress)), provider);
            let allowanceWei = 0n;
            try {
                allowanceWei = asBigInt(await token.allowance(getAddress(String(data.ownerAddress)), getAddress(release.router)));
            } catch {
                allowanceWei = 0n;
            }
            return { success: true, sufficient: allowanceWei >= requiredWei, allowance: allowanceWei.toString(), error: null };
        } catch (err) {
            return { success: false, sufficient: false, error: sanitizeSwapError(err) };
        }
    });

    // Approve the router for the maximum amount (web-app behavior: one-time
    // approval per token / LP token).
    ipcMain.handle("LiquiditySubmitApprove", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet, getAddress, MaxUint256 } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, txHash: null, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, txHash: null, error: "Invalid RPC endpoint" };
            if (!data.privateKey || !data.publicKey) return { success: false, txHash: null, error: "Wallet keys required" };
            if (!data.tokenAddress) return { success: false, txHash: null, error: "Token address required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const privBytes = Buffer.from(data.privateKey, "base64");
            const pubBytes = Buffer.from(data.publicKey, "base64");
            const wallet = Wallet.fromKeys(privBytes, pubBytes, provider);

            const release = resolveSwapReleaseAddresses(data);
            const gasLimit = Number(data.gasLimit) || 84000;
            const token = IERC20.connect(getAddress(String(data.tokenAddress)), wallet);
            const tx = await token.approve(getAddress(release.router), MaxUint256, signingOverrides(wallet, data, { gasLimit }));
            return { success: true, txHash: tx.hash, error: null };
        } catch (err) {
            return { success: false, txHash: null, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("LiquiditySubmitAdd", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet } = loadQuantumCoin();
            const { QuantumSwapV2Router02 } = loadQuantumSwap();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, txHash: null, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, txHash: null, error: "Invalid RPC endpoint" };
            if (!data.privateKey || !data.publicKey) return { success: false, txHash: null, error: "Wallet keys required" };
            if (!data.ownerAddress) return { success: false, txHash: null, error: "Owner address required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const privBytes = Buffer.from(data.privateKey, "base64");
            const pubBytes = Buffer.from(data.publicKey, "base64");
            const wallet = Wallet.fromKeys(privBytes, pubBytes, provider);

            const release = resolveSwapReleaseAddresses(data);
            const call = await buildAddLiquidityCall(data, release, provider);
            const gasLimit = Number(data.gasLimit) || 300000;
            const router: any = QuantumSwapV2Router02.connect(release.router, wallet);
            const overrides = signingOverrides(wallet, data, call.value > 0n ? { gasLimit, value: call.value } : { gasLimit });
            const tx = await router[call.method](...call.args, overrides);
            return { success: true, txHash: tx.hash, error: null };
        } catch (err) {
            return { success: false, txHash: null, error: formatSwapRouterRevertError(err) };
        }
    });

    ipcMain.handle("LiquiditySubmitRemove", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet } = loadQuantumCoin();
            const { QuantumSwapV2Router02 } = loadQuantumSwap();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, txHash: null, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, txHash: null, error: "Invalid RPC endpoint" };
            if (!data.privateKey || !data.publicKey) return { success: false, txHash: null, error: "Wallet keys required" };
            if (!data.ownerAddress) return { success: false, txHash: null, error: "Owner address required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const privBytes = Buffer.from(data.privateKey, "base64");
            const pubBytes = Buffer.from(data.publicKey, "base64");
            const wallet = Wallet.fromKeys(privBytes, pubBytes, provider);

            const release = resolveSwapReleaseAddresses(data);
            const call = await buildRemoveLiquidityCall(data, release, provider);
            const gasLimit = Number(data.gasLimit) || 300000;
            const router: any = QuantumSwapV2Router02.connect(release.router, wallet);
            const tx = await router[call.method](...call.args, signingOverrides(wallet, data, { gasLimit }));
            return { success: true, txHash: tx.hash, error: null };
        } catch (err) {
            return { success: false, txHash: null, error: formatSwapRouterRevertError(err) };
        }
    });

    ipcMain.handle("PoolsSubmitCreatePair", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet, getAddress } = loadQuantumCoin();
            const { QuantumSwapV2Factory } = loadQuantumSwap();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, txHash: null, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, txHash: null, error: "Invalid RPC endpoint" };
            if (!data.privateKey || !data.publicKey) return { success: false, txHash: null, error: "Wallet keys required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const privBytes = Buffer.from(data.privateKey, "base64");
            const pubBytes = Buffer.from(data.publicKey, "base64");
            const wallet = Wallet.fromKeys(privBytes, pubBytes, provider);

            const release = resolveSwapReleaseAddresses(data);
            const tokenAAddress = getAddress(mapSwapTokenValue(String(data.tokenAValue), release));
            const tokenBAddress = getAddress(mapSwapTokenValue(String(data.tokenBValue), release));
            if (tokenAAddress.toLowerCase() === tokenBAddress.toLowerCase()) {
                return { success: false, txHash: null, error: "Identical tokens" };
            }
            const gasLimit = Number(data.gasLimit) || 3000000;
            const factory = QuantumSwapV2Factory.connect(release.factory, wallet);
            const tx = await factory.createPair(tokenAAddress, tokenBAddress, signingOverrides(wallet, data, { gasLimit }));
            return { success: true, txHash: tx.hash, error: null };
        } catch (err) {
            return { success: false, txHash: null, error: sanitizeSwapError(err) };
        }
    });

    // Deploy the CreatedToken contract. The contract address is deterministic
    // from (from, nonce) - same computation the SDK's ContractFactory.deploy
    // uses - so it is returned immediately alongside the tx hash.
    ipcMain.handle("TokenSubmitCreate", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet, getCreateAddress } = loadQuantumCoin();
            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, txHash: null, contractAddress: null, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, txHash: null, contractAddress: null, error: "Invalid RPC endpoint" };
            if (!data.privateKey || !data.publicKey) return { success: false, txHash: null, contractAddress: null, error: "Wallet keys required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const privBytes = Buffer.from(data.privateKey, "base64");
            const pubBytes = Buffer.from(data.publicKey, "base64");
            const wallet = Wallet.fromKeys(privBytes, pubBytes, provider);

            const inputs = parseDeployTokenInputs(data);
            const deployTx = buildDeployTokenTx(inputs, wallet);
            const from = wallet.address || (typeof wallet.getAddress === "function" ? await wallet.getAddress() : null);
            if (!from) return { success: false, txHash: null, contractAddress: null, error: "Unable to resolve wallet address" };
            let nonce: number;
            try {
                nonce = await provider.getTransactionCount(from, "pending");
            } catch {
                nonce = await provider.getTransactionCount(from, "latest");
            }
            const contractAddress = getCreateAddress({ from, nonce });
            const gasLimit = Number(data.gasLimit) || 6000000;
            const tx = await wallet.sendTransaction(signingOverrides(wallet, data, { ...deployTx, nonce, gasLimit }));
            return { success: true, txHash: tx.hash, contractAddress, error: null };
        } catch (err) {
            return { success: false, txHash: null, contractAddress: null, error: sanitizeSwapError(err) };
        }
    });
}
