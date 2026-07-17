import { ipcMain } from "electron";
import { loadQuantumCoin, loadQuantumCoinConfig, loadQuantumSwap } from "../sdk";
import {
    createQuantumRpcProvider,
    initRpcUrlForConfig,
    resolveSwapReleaseAddresses,
    sanitizeSwapError,
    formatSwapRouterRevertError,
    getSwapTxDeadline,
    normalizeAmountString,
    signingOverrides,
} from "../rpc";
import { findSwapPath, getSwapPathSymbols, mapSwapTokenValue, resolveSwapPath } from "../swap-routing";

export function registerSwapHandlers(): void {
    ipcMain.handle("SwapTokenGetMetadata", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { getAddress, formatUnits } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, error: "Invalid chain ID" };
            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const contractAddress = getAddress(String(data.contractAddress || ""));
            const ownerAddress = data.ownerAddress ? getAddress(String(data.ownerAddress)) : null;
            const token = IERC20.connect(contractAddress, provider);
            let nameValue = "";
            try {
                if (typeof token.name === "function") nameValue = String(await token.name());
            } catch {
                // name() is optional metadata; symbol/decimals identify the token.
            }
            const [symbolValue, decimalsValue, balanceValue] = await Promise.all([
                token.symbol(),
                token.decimals(),
                ownerAddress == null ? Promise.resolve(0n) : token.balanceOf(ownerAddress),
            ]);
            const decimals = Number(decimalsValue);
            if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
                return { success: false, error: "Invalid token decimals" };
            }
            return {
                success: true,
                contractAddress,
                name: String(nameValue || ""),
                symbol: String(symbolValue || ""),
                decimals,
                balance: formatUnits(balanceValue, decimals),
                error: null,
            };
        } catch (err) {
            return { success: false, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("SwapQuoteGetAmountsOut", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { parseUnits, formatUnits } = loadQuantumCoin();
            const { QuantumSwapV2Router02 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const router = QuantumSwapV2Router02.connect(release.router, provider);

            const path = await resolveSwapPath(provider, chainId, data.fromTokenValue, data.toTokenValue, release);

            const fromDecimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const toDecimals = typeof data.toDecimals === "number" ? data.toDecimals : 18;
            const amountInWei = parseUnits(String(data.amountIn), fromDecimals);

            const amounts = await router.getAmountsOut(amountInWei, path);
            const amountOutWei = Array.isArray(amounts) ? amounts[amounts.length - 1] : amounts;
            const amountOut = formatUnits(amountOutWei, toDecimals);

            return { success: true, amountOut };
        } catch (err) {
            return { success: false, error: sanitizeSwapError(err) };
        }
    });

    // Route check: `exists` is true when a direct pair OR a multi-hop route (max
    // 3 intermediates) exists. `path` is the address route and `pathSymbols` the
    // on-chain symbol for each path token (null entries when the lookup failed).
    // Symbols are untrusted; the UI sanitizes before display.
    ipcMain.handle("SwapQuoteCheckPairExists", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { exists: false, path: null, pathSymbols: null, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { exists: false, path: null, pathSymbols: null, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const path = await findSwapPath(
                provider,
                chainId,
                mapSwapTokenValue(data.fromTokenValue, release),
                mapSwapTokenValue(data.toTokenValue, release),
                release
            );
            if (!path) return { exists: false, path: null, pathSymbols: null, error: null };

            const pathSymbols = await getSwapPathSymbols(provider, chainId, path);
            return { exists: true, path, pathSymbols, error: null };
        } catch (err) {
            return { exists: false, path: null, pathSymbols: null, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("SwapQuoteGetAmountsIn", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { parseUnits, formatUnits } = loadQuantumCoin();
            const { QuantumSwapV2Router02 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const router = QuantumSwapV2Router02.connect(release.router, provider);

            const path = await resolveSwapPath(provider, chainId, data.fromTokenValue, data.toTokenValue, release);

            const fromDecimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const toDecimals = typeof data.toDecimals === "number" ? data.toDecimals : 18;
            const amountOutWei = parseUnits(String(data.amountOut), toDecimals);

            const amounts = await router.getAmountsIn(amountOutWei, path);
            const amountInWei = Array.isArray(amounts) ? amounts[0] : amounts;
            const amountIn = formatUnits(amountInWei, fromDecimals);

            return { success: true, amountIn };
        } catch (err) {
            return { success: false, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("SwapQuoteEstimateGas", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { parseUnits, getAddress } = loadQuantumCoin();
            const { QuantumSwapV2Router02 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, gasLimit: null, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, gasLimit: null, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const router = QuantumSwapV2Router02.connect(release.router, provider);

            const path = await resolveSwapPath(provider, chainId, data.fromTokenValue, data.toTokenValue, release);
            const fromDecimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const toDecimals = typeof data.toDecimals === "number" ? data.toDecimals : 18;
            const toAddress = data.recipientAddress || data.toAddress;
            if (!toAddress) return { success: false, gasLimit: null, error: "Recipient address required" };
            const deadline = await getSwapTxDeadline(provider, 1200);
            const lastChanged = data.lastChanged === "to" ? "to" : "from";
            const slippagePercent = Math.max(0, Math.min(100, Number(data.slippagePercent) || 1));

            let amountInWei;
            let amountOutMinWei;
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
                amountInWei,
                amountOutMinWei,
                path,
                getAddress(toAddress),
                deadline
            );
            const txWithFrom = { ...tx, from: getAddress(toAddress) };
            const gasLimit = await provider.estimateGas(txWithFrom);
            const gasLimitStr = typeof gasLimit === "bigint" ? gasLimit.toString() : String(gasLimit);
            return { success: true, gasLimit: gasLimitStr, error: null };
        } catch (err) {
            return { success: false, gasLimit: null, error: formatSwapRouterRevertError(err) };
        }
    });

    ipcMain.handle("SwapQuoteCheckAllowance", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { parseUnits, getAddress } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, sufficient: false, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, sufficient: false, error: "Invalid RPC endpoint" };
            if (!data.ownerAddress) return { success: false, sufficient: false, error: "Owner address required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const tokenAddr = mapSwapTokenValue(data.fromTokenValue, release);
            const spenderAddr = release.router;
            const decimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const requiredWei = parseUnits(normalizeAmountString(data.requiredAmount), decimals);
            const token = IERC20.connect(getAddress(tokenAddr), provider);
            let allowanceWei;
            if (typeof token.allowance !== "function") {
                allowanceWei = 0n;
            } else {
                try {
                    allowanceWei = await token.allowance(getAddress(data.ownerAddress), getAddress(spenderAddr));
                } catch {
                    allowanceWei = 0n;
                }
            }
            const allowanceStr = typeof allowanceWei === "bigint" ? allowanceWei.toString() : String(allowanceWei);
            const sufficient = (typeof allowanceWei === "bigint" ? allowanceWei : BigInt(allowanceStr)) >= requiredWei;
            return { success: true, sufficient, allowance: allowanceStr, error: null };
        } catch (err) {
            return { success: false, sufficient: false, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("SwapQuoteEstimateApproveGas", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { parseUnits, getAddress } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, gasLimit: null, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, gasLimit: null, error: "Invalid RPC endpoint" };
            if (!data.fromAddress) return { success: false, gasLimit: null, error: "From address required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const tokenAddr = mapSwapTokenValue(data.fromTokenValue, release);
            const spenderAddr = release.router;
            const decimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const amountWei = parseUnits(normalizeAmountString(data.amount), decimals);

            const token = IERC20.connect(getAddress(tokenAddr), provider);
            const tx = await token.populateTransaction.approve(getAddress(spenderAddr), amountWei);
            const txWithFrom = { ...tx, from: getAddress(data.fromAddress) };
            const gasLimit = await provider.estimateGas(txWithFrom);
            const gasLimitStr = typeof gasLimit === "bigint" ? gasLimit.toString() : String(gasLimit);
            return { success: true, gasLimit: gasLimitStr, error: null };
        } catch (err) {
            return { success: false, gasLimit: null, error: sanitizeSwapError(err) };
        }
    });

    // Returns the active release's router (payload may carry release overrides).
    ipcMain.handle("SwapQuoteGetRouterAddress", async (_event, data) => {
        try {
            const release = resolveSwapReleaseAddresses(data);
            return { success: true, routerAddress: release.router, error: null };
        } catch (err) {
            return { success: false, routerAddress: null, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("SwapQuoteGetSwapContractData", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { parseUnits, getAddress } = loadQuantumCoin();
            const { QuantumSwapV2Router02 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, dataHex: null, toAddress: null, valueHex: null, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, dataHex: null, toAddress: null, valueHex: null, error: "Invalid RPC endpoint" };
            const toAddress = data.recipientAddress || data.toAddress;
            if (!toAddress) return { success: false, dataHex: null, toAddress: null, valueHex: null, error: "Recipient address required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const router = QuantumSwapV2Router02.connect(release.router, provider);

            const path = await resolveSwapPath(provider, chainId, data.fromTokenValue, data.toTokenValue, release);
            const fromDecimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const toDecimals = typeof data.toDecimals === "number" ? data.toDecimals : 18;
            const deadline = await getSwapTxDeadline(provider, 1200);
            const lastChanged = data.lastChanged === "to" ? "to" : "from";
            const slippagePercent = Math.max(0, Math.min(100, Number(data.slippagePercent) || 1));

            let amountInWei;
            let amountOutMinWei;
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
                amountInWei,
                amountOutMinWei,
                path,
                getAddress(toAddress),
                deadline
            );
            const dataHex = tx && tx.data ? (typeof tx.data === "string" ? tx.data : String(tx.data)) : null;
            if (!dataHex) return { success: false, dataHex: null, toAddress: null, valueHex: null, error: "No contract data" };
            const valueHex = tx.value != null && tx.value !== 0n ? "0x" + tx.value.toString(16) : "0x0";
            return { success: true, dataHex, toAddress: release.router, valueHex, error: null };
        } catch (err) {
            return { success: false, dataHex: null, toAddress: null, valueHex: null, error: formatSwapRouterRevertError(err) };
        }
    });

    ipcMain.handle("SwapQuoteGetApproveContractData", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { parseUnits, getAddress } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, dataHex: null, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, dataHex: null, error: "Invalid RPC endpoint" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const release = resolveSwapReleaseAddresses(data);
            const tokenAddr = mapSwapTokenValue(data.fromTokenValue, release);
            const spenderAddr = release.router;
            const decimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const amountWei = parseUnits(normalizeAmountString(data.amount), decimals);

            const token = IERC20.connect(getAddress(tokenAddr), provider);
            const tx = await token.populateTransaction.approve(getAddress(spenderAddr), amountWei);
            const dataHex = tx && tx.data ? (typeof tx.data === "string" ? tx.data : String(tx.data)) : null;
            if (!dataHex) return { success: false, dataHex: null, tokenAddress: null, error: "No contract data" };
            return { success: true, dataHex, tokenAddress: tokenAddr, error: null };
        } catch (err) {
            return { success: false, dataHex: null, tokenAddress: null, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("SwapSubmitApproval", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet, parseUnits, getAddress } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();

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
            const tokenAddr = mapSwapTokenValue(data.fromTokenValue, release);
            const decimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const amountWei = parseUnits(normalizeAmountString(data.amount), decimals);
            const gasLimit = Number(data.gasLimit) || 84000;

            const token = IERC20.connect(getAddress(tokenAddr), wallet);
            const tx = await token.approve(getAddress(release.router), amountWei, signingOverrides(wallet, data, { gasLimit }));
            return { success: true, txHash: tx.hash, error: null };
        } catch (err) {
            return { success: false, txHash: null, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("SwapSubmitSwap", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet, parseUnits, getAddress } = loadQuantumCoin();
            const { QuantumSwapV2Router02 } = loadQuantumSwap();

            const chainId = Number(data.chainId);
            if (!Number.isInteger(chainId)) return { success: false, txHash: null, error: "Invalid chain ID" };

            const provider = createQuantumRpcProvider(data.rpcEndpoint, chainId);
            if (!provider) return { success: false, txHash: null, error: "Invalid RPC endpoint" };
            const recipientAddress = data.recipientAddress;
            if (!recipientAddress) return { success: false, txHash: null, error: "Recipient address required" };
            if (!data.privateKey || !data.publicKey) return { success: false, txHash: null, error: "Wallet keys required" };

            await Initialize(new Config(chainId, initRpcUrlForConfig(data.rpcEndpoint)));
            const privBytes = Buffer.from(data.privateKey, "base64");
            const pubBytes = Buffer.from(data.publicKey, "base64");
            const wallet = Wallet.fromKeys(privBytes, pubBytes, provider);

            const release = resolveSwapReleaseAddresses(data);
            const router = QuantumSwapV2Router02.connect(release.router, wallet);
            const path = await resolveSwapPath(provider, chainId, data.fromTokenValue, data.toTokenValue, release);
            const fromDecimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const toDecimals = typeof data.toDecimals === "number" ? data.toDecimals : 18;
            const deadline = await getSwapTxDeadline(provider, 1200);
            const lastChanged = data.lastChanged === "to" ? "to" : "from";
            const slippagePercent = Math.max(0, Math.min(100, Number(data.slippagePercent) || 1));
            const gasLimit = Number(data.gasLimit) || 200000;

            let amountInWei;
            let amountOutMinWei;
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

            const tx = await router.swapExactTokensForTokens(
                amountInWei,
                amountOutMinWei,
                path,
                getAddress(recipientAddress),
                deadline,
                signingOverrides(wallet, data, { gasLimit })
            );
            return { success: true, txHash: tx.hash, error: null };
        } catch (err) {
            return { success: false, txHash: null, error: formatSwapRouterRevertError(err) };
        }
    });

    ipcMain.handle("SwapSubmitRemoveAllowance", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet, getAddress } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();

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
            const tokenAddr = mapSwapTokenValue(data.fromTokenValue, release);
            const gasLimit = Number(data.gasLimit) || 84000;

            const token = IERC20.connect(getAddress(tokenAddr), wallet);
            const tx = await token.approve(getAddress(release.router), 0n, signingOverrides(wallet, data, { gasLimit }));
            return { success: true, txHash: tx.hash, error: null };
        } catch (err) {
            return { success: false, txHash: null, error: sanitizeSwapError(err) };
        }
    });

    ipcMain.handle("SwapSubmitAddAllowance", async (_event, data) => {
        try {
            const { Initialize, Config } = loadQuantumCoinConfig();
            const { Wallet, parseUnits, getAddress } = loadQuantumCoin();
            const { IERC20 } = loadQuantumSwap();

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
            const tokenAddr = mapSwapTokenValue(data.fromTokenValue, release);
            const decimals = typeof data.fromDecimals === "number" ? data.fromDecimals : 18;
            const amountWei = parseUnits(normalizeAmountString(data.amount), decimals);
            const gasLimit = Number(data.gasLimit) || 84000;

            const token = IERC20.connect(getAddress(tokenAddr), wallet);
            const tx = await token.approve(getAddress(release.router), amountWei, signingOverrides(wallet, data, { gasLimit }));
            return { success: true, txHash: tx.hash, error: null };
        } catch (err) {
            return { success: false, txHash: null, error: sanitizeSwapError(err) };
        }
    });
}
