// Typed async wrappers over the IPC APIs exposed by the preload script.
// 1:1 port of the old src/js/bridge.js.

export async function WriteTextToClipboard(text: string): Promise<void> {
    await ClipboardApi.send("ClipboardWriteText", text);
}

export async function OpenUrl(url: string): Promise<boolean> {
    try {
        await ShellApi.send("OpenUrlInShell", url);
    } catch (e) {
        console.log(e);
    }
    return false;
}

export async function GetAppVersion(): Promise<string> {
    return await AppApi.send("AppApiGetVersion", null);
}

export async function GetPackageName(): Promise<string> {
    return await AppApi.send("AppApiGetPackageName", null);
}

export async function ReadFile(seedfile: string): Promise<string | null> {
    return await FileApi.send("FileApiReadFile", seedfile);
}

export async function getLocalStoragePath(): Promise<string> {
    return await LocalStorageApi.send("StorageApiGetPath", null);
}

export async function weiToEther(wei: string): Promise<string> {
    return await FormatApi.send("FormatApiWeiToEther", wei);
}

export async function etherToWei(eth: string): Promise<string> {
    return await FormatApi.send("FormatApiEtherToWei", eth);
}

export function commify(value: string): string {
    const match = value.match(/^(-?)([0-9]*)(\.?)([0-9]*)$/);
    if (!match || (!match[2] && !match[4])) {
        throw new Error(`bad formatted number: ${JSON.stringify(value)}`);
    }

    const neg = match[1];
    const whole = BigInt(match[2] || 0).toLocaleString("en-us");
    const frac = match[4] ? (match[4].match(/^(.*?)0*$/) as RegExpMatchArray)[1] : "0";

    return `${neg}${whole}.${frac}`;
}

export async function weiToEtherFormatted(wei: string): Promise<string> {
    let eth: string = await FormatApi.send("FormatApiWeiToEther", wei);
    eth = commify(eth);

    if (eth.endsWith(".")) {
        eth = eth.substring(0, eth.length - 1);
    }

    return eth;
}

export async function hexWeiToEthFormatted(hex: string): Promise<string> {
    const wei = BigInt(hex).toString();
    return await weiToEtherFormatted(wei);
}

export async function isValidEther(quantity: string): Promise<boolean> {
    return await FormatApi.send("FormatApiIsValidEther", quantity);
}

export async function compareEther(val1: string, val2: string): Promise<number> {
    return await FormatApi.send("FormatApiCompareEther", { num1: val1, num2: val2 });
}

export async function getSwapQuoteAmountsOut(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapQuoteGetAmountsOut", payload);
}

export async function getSwapQuoteAmountsIn(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapQuoteGetAmountsIn", payload);
}

// Route check result: `exists` is true when a direct pair OR a multi-hop route
// exists. `path` is the address route ([from, ...hops, to]) and `pathSymbols`
// the on-chain symbol per path token (null entries when the lookup failed).
// Symbols are untrusted RPC data; sanitize before display.
export interface SwapCheckPairExistsResult {
    exists: boolean;
    path: string[] | null;
    pathSymbols: (string | null)[] | null;
    error: string | null;
}

export async function getSwapCheckPairExists(payload: unknown): Promise<SwapCheckPairExistsResult> {
    return await SwapQuoteApi.send("SwapQuoteCheckPairExists", payload);
}

export async function getSwapEstimateGas(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapQuoteEstimateGas", payload);
}

export async function getSwapCheckAllowance(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapQuoteCheckAllowance", payload);
}

export async function getSwapEstimateApproveGas(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapQuoteEstimateApproveGas", payload);
}

export async function estimateGas(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("estimateGas", payload);
}

export async function estimateGasFee(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("estimateGasFee", payload);
}

export async function getSwapApproveContractData(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapQuoteGetApproveContractData", payload);
}

export async function getSwapRouterAddress(payload: unknown = {}): Promise<any> {
    return await SwapQuoteApi.send("SwapQuoteGetRouterAddress", payload);
}

export async function getSwapSwapContractData(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapQuoteGetSwapContractData", payload);
}

export async function submitSwapApproval(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapSubmitApproval", payload);
}

export async function submitSwapSwap(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapSubmitSwap", payload);
}

export async function submitSwapRemoveAllowance(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapSubmitRemoveAllowance", payload);
}

export async function submitSwapAddAllowance(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SwapSubmitAddAllowance", payload);
}

// Liquidity / pools / token creation (Settings -> Advanced screens).

// Snapshot of a factory pair as returned by the main process. Reserve /
// supply values are base-unit (wei) strings; symbols are untrusted on-chain
// data and must be sanitized before display.
export interface LiquidityPairSnapshot {
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

export interface LiquidityPositionSnapshot extends LiquidityPairSnapshot {
    lpBalance: string;
}

export async function getLiquidityPools(payload: unknown): Promise<{ success: boolean; pools: LiquidityPairSnapshot[] | null; error: string | null }> {
    return await SwapQuoteApi.send("LiquidityListPools", payload);
}

export async function getLiquidityPositions(payload: unknown): Promise<{ success: boolean; positions: LiquidityPositionSnapshot[] | null; error: string | null }> {
    return await SwapQuoteApi.send("LiquidityListPositions", payload);
}

export interface LiquidityPairInfoResult {
    success: boolean;
    exists: boolean;
    tokenAAddress?: string;
    tokenBAddress?: string;
    pair?: LiquidityPairSnapshot | null;
    lpBalance?: string | null;
    error: string | null;
}

export async function getLiquidityPairInfo(payload: unknown): Promise<LiquidityPairInfoResult> {
    return await SwapQuoteApi.send("LiquidityGetPairInfo", payload);
}

export async function getLiquidityCheckAllowance(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("LiquidityCheckAllowance", payload);
}

export async function submitLiquidityApprove(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("LiquiditySubmitApprove", payload);
}

export async function submitLiquidityAdd(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("LiquiditySubmitAdd", payload);
}

export async function submitLiquidityRemove(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("LiquiditySubmitRemove", payload);
}

export async function submitPoolsCreatePair(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("PoolsSubmitCreatePair", payload);
}

export async function submitTokenCreate(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("TokenSubmitCreate", payload);
}

export async function submitSendCoins(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SendCoinsSubmit", payload);
}

export async function submitSendTokens(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("SendTokensSubmit", payload);
}

export async function offlineSignCoinTransaction(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("OfflineSignCoinTransaction", payload);
}

export async function offlineSignTokenTransaction(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("OfflineSignTokenTransaction", payload);
}

export async function submitStakingContract(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("StakingContractSubmit", payload);
}

export async function offlineSignStakingContract(payload: unknown): Promise<any> {
    return await SwapQuoteApi.send("StakingContractOfflineSign", payload);
}

export async function cryptoRandomBytes(size: number): Promise<string> {
    return await CryptoApi.send("CryptoRandomBytes", size);
}

export async function walletFromSeed(seedArray: Uint8Array | number[]): Promise<{ address: string; privateKey: string; publicKey: string }> {
    return await CryptoApi.send("WalletFromSeed", { seed: Array.from(seedArray) });
}

export async function walletEncryptJson(privateKeyBase64: string, publicKeyBase64: string, passphrase: string): Promise<string> {
    return await CryptoApi.send("WalletEncryptJson", {
        privateKey: privateKeyBase64,
        publicKey: publicKeyBase64,
        passphrase: passphrase,
    });
}

export async function walletDecryptJson(json: string, passphrase: string): Promise<{ address: string; privateKey: string; publicKey: string; seed: string | null }> {
    return await CryptoApi.send("WalletDecryptJson", { json: json, passphrase: passphrase });
}

export async function computeAddressFromPublicKey(publicKeyBase64: string): Promise<string> {
    return await CryptoApi.send("ComputeAddress", publicKeyBase64);
}

export async function scryptDerive(secret: string, saltBase64: string): Promise<string> {
    return await CryptoApi.send("ScryptDerive", { secret: secret, salt: saltBase64 });
}
