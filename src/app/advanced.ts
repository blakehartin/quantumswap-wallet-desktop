// Settings -> Advanced: token creation, pool browsing / pair creation, and
// add/remove liquidity with a positions list. Ported from the
// quantumswap-web-app views (createToken / poolExplorer / createPair /
// addLiquidity / removeLiquidity / positions), using the desktop's review
// dialog for confirmation + password and the numbered tx-steps dialog
// (app/txsteps.ts) for execution.
import { langJson } from "../lib/i18n";
import { htmlEncode, containsUnsafeDisplayText } from "../lib/util";
import { impersonatesStablecoin } from "../lib/tokenfilter";
import { walletGetByAddress } from "../lib/wallet";
import {
    LiquidityPairInfoResult,
    LiquidityPairSnapshot,
    LiquidityPositionSnapshot,
    OpenUrl,
    WriteTextToClipboard,
    getLiquidityCheckAllowance,
    getLiquidityPairInfo,
    getLiquidityPools,
    getLiquidityPositions,
    submitLiquidityAdd,
    submitLiquidityApprove,
    submitLiquidityRemove,
    submitPoolsCreatePair,
    submitTokenCreate,
} from "../lib/bridge";
import {
    formatBaseUnits,
    minWithSlippage,
    parseBaseUnits,
    percentOfAmount,
    poolSharePercent,
    positionUnderlying,
    quote,
} from "../lib/liquidity-math";
import {
    ADDRESS_TEMPLATE,
    BLOCK_EXPLORER_ACCOUNT_TEMPLATE,
    BLOCK_EXPLORER_DOMAIN_TEMPLATE,
    GasState,
    TxContext,
    byId,
    getShortAddress,
    inputById,
    networkStore,
    selectById,
    walletStore,
} from "./state";
import {
    TransactionReview,
    hideWaitingBox,
    showLoadingAndExecuteAsync,
    showWaitingBox,
    showTransactionReviewDialog,
    showWarnAlert,
    txReviewNetworkText,
} from "./dialog";
import { TxStepDefinition, showTxStepsDialog } from "./txsteps";
import {
    APPROVE_DEFAULT_GAS,
    estimateGasForContext,
    onGasIconClick,
    resetCurrentGasConfig,
    resolveGasForTx,
    scheduleGasEstimation,
    setGasFeeLabel,
} from "./gas";
import { getGenericError, OpenScanAddress, removeOptions, setHeaderBand } from "./app";
import { getSwapBalanceForSymbol, getSwapRouteDisplaySymbol, getSwapTokenDecimals, getSwapTokenListFromWallet } from "./swap";
import { advancedSigningGetDefaultValue } from "./settings";
import { applySwapReleaseToPayload, currentSwapRelease } from "./release";
import { BUILTIN_SWAP_RELEASES } from "../lib/release";

// Hardcoded gas-limit fallbacks, used when estimateGas fails (e.g. the
// estimate reverts because a required approval has not run yet).
export const ADD_LIQUIDITY_DEFAULT_GAS = 600000;
// First deposit makes the router deploy the pair contract; same for an
// explicit factory.createPair.
export const CREATE_PAIR_DEFAULT_GAS = 4500000;
export const REMOVE_LIQUIDITY_DEFAULT_GAS = 600000;
export const DEPLOY_TOKEN_DEFAULT_GAS = 6000000;

const LP_TOKEN_DECIMALS = 18;

function t(key: string, fallback: string): string {
    return (langJson && langJson.langValues && langJson.langValues[key]) || fallback;
}

function chainPayload(): Record<string, unknown> {
    const net = networkStore.currentBlockchainNetwork as { rpcEndpoint: string; networkId: number };
    return applySwapReleaseToPayload({
        rpcEndpoint: net.rpcEndpoint,
        chainId: parseInt(String(net.networkId), 10),
    });
}

function activeWqAddress(): string {
    return (currentSwapRelease && currentSwapRelease.wq) ? String(currentSwapRelease.wq) : String(BUILTIN_SWAP_RELEASES[0].wq);
}

// Picker value ("Q" or a contract address) decimals / display symbol.
function tokenValueDecimals(value: string): number {
    return value === "Q" ? 18 : getSwapTokenDecimals(value);
}

const advancedTokenSymbolCache = new Map<string, string>([["q", "Q"]]);

function tokenValueSymbol(value: string): string {
    const cached = advancedTokenSymbolCache.get(String(value).toLowerCase());
    return cached || (value === "Q" ? "Q" : getSwapRouteDisplaySymbol(value, null));
}

// Map an on-chain pair token address back to a picker value: the active
// release's WQ shows as native Q, everything else keeps its address.
function pickerValueForTokenAddress(address: string): string {
    return address.toLowerCase() === activeWqAddress().toLowerCase() ? "Q" : address;
}

function pairTokenSymbol(address: string, symbol: string | null): string {
    if (address.toLowerCase() === activeWqAddress().toLowerCase()) return "Q";
    return getSwapRouteDisplaySymbol(address, symbol);
}

function populateTokenPicker(selectId: string): void {
    const ddl = selectById(selectId);
    const previous = ddl.value;
    removeOptions(ddl);
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.text = t("select-token", "Select token");
    ddl.add(placeholder);
    const list = getSwapTokenListFromWallet();
    for (const item of list) {
        const opt = document.createElement("option");
        opt.value = item.value;
        opt.text = item.displayText;
        ddl.add(opt);
        advancedTokenSymbolCache.set(
            item.value.toLowerCase(),
            item.value === "Q" ? "Q" : getSwapRouteDisplaySymbol(item.value, null),
        );
    }
    if (previous) ddl.value = previous;
}

// Select a picker option by value, matching addresses case-insensitively
// (chain addresses are checksummed; wallet-list values may differ in case).
function setPickerValue(selectId: string, value: string): void {
    const ddl = selectById(selectId);
    const lower = value.toLowerCase();
    for (let i = 0; i < ddl.options.length; i++) {
        if (ddl.options[i].value.toLowerCase() === lower) {
            ddl.selectedIndex = i;
            return;
        }
    }
}

function explorerAccountUrl(address: string): string | null {
    if (!networkStore.currentBlockchainNetwork) return null;
    return BLOCK_EXPLORER_ACCOUNT_TEMPLATE
        .replace(BLOCK_EXPLORER_DOMAIN_TEMPLATE, (networkStore.currentBlockchainNetwork as { blockExplorerDomain: string }).blockExplorerDomain)
        .replace(ADDRESS_TEMPLATE, address);
}

// Short-address explorer link (createElement/textContent only; the address is
// on-chain data used verbatim in the URL, same pattern as the releases table).
function explorerAddressLink(address: string): HTMLElement {
    const url = explorerAccountUrl(address);
    if (url == null) {
        const span = document.createElement("span");
        span.textContent = getShortAddress(address);
        span.title = address;
        return span;
    }
    const link = document.createElement("a");
    link.href = url;
    link.textContent = getShortAddress(address);
    link.title = address;
    link.addEventListener("click", function (ev: Event) {
        ev.preventDefault();
        void OpenUrl(url);
        return false;
    });
    return link;
}

// Keep a text input numeric: digits and at most one decimal point (same
// cleaning as the gas dialog's fee field). Call first in oninput handlers.
function sanitizeNumericInput(input: HTMLInputElement): void {
    const v = input.value;
    let cleaned = v.replace(/[^0-9.]/g, "");
    const parts = cleaned.split(".");
    if (parts.length > 2) cleaned = parts[0] + "." + parts.slice(1).join("");
    if (cleaned !== v) input.value = cleaned;
}

function setInlineError(divId: string, message: string | null): void {
    const div = byId(divId);
    if (message == null || message === "") {
        div.style.display = "none";
        div.textContent = "";
        return;
    }
    div.textContent = message;
    div.style.display = "block";
}

// ---------------- Gas states (one per flow, like the swap sub-flows) ----------------

export const createTokenGasState: GasState = { gasLimit: null, gasFee: null, overridden: false };
export const createPairGasState: GasState = { gasLimit: null, gasFee: null, overridden: false };

// Tx-context providers: null until the form holds enough valid input to
// estimate. runGasEstimation falls back to defaultGasLimit when the RPC
// estimate reverts (e.g. approvals not yet granted).

function getCreateTokenTxContext(): TxContext | null {
    const name = (inputById("txtCreateTokenName").value || "").trim();
    const symbol = (inputById("txtCreateTokenSymbol").value || "").trim();
    const decimals = parseInt(selectById("ddlCreateTokenDecimals").value, 10);
    const supply = (inputById("txtCreateTokenSupply").value || "").trim();
    if (name.length < 1 || !/^[A-Za-z0-9]{1,16}$/.test(symbol)) return null;
    if (!Number.isInteger(decimals) || decimals < 1 || decimals > 18) return null;
    try {
        if (parseBaseUnits(supply, decimals) <= 0n) return null;
    } catch {
        return null;
    }
    return {
        txKind: "deployToken",
        defaultGasLimit: DEPLOY_TOKEN_DEFAULT_GAS,
        name,
        symbol,
        decimals,
        totalSupply: supply,
    };
}

function getCreatePairTxContext(): TxContext | null {
    const a = selectById("ddlPoolsTokenA").value;
    const b = selectById("ddlPoolsTokenB").value;
    if (!a || !b || a === b) return null;
    return {
        txKind: "createPair",
        defaultGasLimit: CREATE_PAIR_DEFAULT_GAS,
        tokenAValue: a,
        tokenBValue: b,
    };
}

function scheduleCreateTokenGas(): void {
    scheduleGasEstimation(getCreateTokenTxContext, "divCreateTokenGasIcon", "spanCreateTokenGasFee", createTokenGasState);
}

function scheduleCreatePairGas(): void {
    scheduleGasEstimation(getCreatePairTxContext, "divCreatePairGasIcon", "spanCreatePairGasFee", createPairGasState);
}

export function onCreateTokenInput(): void {
    sanitizeNumericInput(inputById("txtCreateTokenSupply"));
    scheduleCreateTokenGas();
}

export function onLiquiditySlippageInput(): void {
    sanitizeNumericInput(inputById("txtLiquiditySlippage"));
}

export function onRemoveSlippageInput(): void {
    sanitizeNumericInput(inputById("txtLiquidityRemoveSlippage"));
}

export function onCreateTokenGasIconClick(): boolean {
    return onGasIconClick("spanCreateTokenGasFee", createTokenGasState, getCreateTokenTxContext);
}

export function onCreatePairGasIconClick(): boolean {
    return onGasIconClick("spanCreatePairGasFee", createPairGasState, getCreatePairTxContext);
}

// ---------------- Balance / contract rows under the token pickers ----------------

// Update the "Balance: N" + full-contract-address rows under a token picker
// (suffix is PoolsA / PoolsB / LiquidityA / LiquidityB).
async function updatePickerInfoRows(suffix: string, value: string): Promise<void> {
    const balanceRow = byId("divAdvBalanceRow" + suffix);
    const contractRow = byId("divAdvContractRow" + suffix);
    if (!value) {
        balanceRow.style.display = "none";
        contractRow.style.display = "none";
        return;
    }
    if (value === "Q") {
        contractRow.style.display = "none";
    } else {
        const link = byId<HTMLAnchorElement>("aAdvContract" + suffix);
        link.textContent = value;
        link.onclick = function (ev: Event) {
            ev.preventDefault();
            const url = explorerAccountUrl(value);
            if (url != null) void OpenUrl(url);
            return false;
        };
        byId("divAdvCopyContract" + suffix).onclick = function () {
            void WriteTextToClipboard(value);
        };
        contractRow.style.display = "flex";
    }
    const balance = await getSwapBalanceForSymbol(value);
    byId("spanAdvBalance" + suffix).textContent = balance;
    balanceRow.style.display = "block";
}

// Shared review-dialog -> steps-dialog handoff: the review collects the typed
// "i agree" + wallet password once; the wallet keys are decrypted once and the
// steps then run automatically or wait for user-driven per-step actions.
interface ReviewedStepsFlow {
    review: TransactionReview;
    stepsTitle: string;
    progressText?: string;
    interactive?: boolean;
    buildSteps: (privateKey: string, publicKey: string, advancedSigningEnabled: boolean) => TxStepDefinition[];
    onAllDone?: () => HTMLElement | null | void;
    onClose?: () => unknown;
}

function showReviewThenSteps(flow: ReviewedStepsFlow): void {
    const review = flow.review;
    review.requirePassword = true;
    review.submitLabelKey = "submit";
    review.nonce = null;
    review.networkText = txReviewNetworkText();
    review.fromAddress = walletStore.currentWalletAddress;
    if (flow.interactive) review.showGas = false;
    review.onSubmit = async function (): Promise<boolean> {
        showWaitingBox(langJson.langValues.waitWalletOpen);
        try {
            const password = (inputById("txtTxReviewPassword").value || "").trim();
            const quantumWallet = await walletGetByAddress(password, walletStore.currentWalletAddress);
            if (quantumWallet == null) {
                showWarnAlert(getGenericError(""));
                return false;
            }
            const privateKey = await quantumWallet.getPrivateKey();
            const publicKey = await quantumWallet.getPublicKey();
            const advancedSigningEnabled = await advancedSigningGetDefaultValue();
            const steps = flow.buildSteps(privateKey, publicKey, advancedSigningEnabled === true);
            // Close the decrypt wait dialog now; open the status UI on the next
            // turn so the review dialog can finish closing first (avoids Close
            // overlapping unpainted step labels).
            hideWaitingBox();
            const stepsTitle = flow.stepsTitle;
            const progressText = flow.progressText;
            const onAllDone = flow.onAllDone;
            const onClose = flow.onClose;
            const clearStepSecretsAndClose = function (): void {
                // Sever closures that capture decrypted keys as soon as the
                // workflow dialog closes.
                for (const step of steps) {
                    step.prepare = undefined;
                    step.run = async () => { throw new Error("Workflow closed."); };
                }
                if (onClose) void onClose();
            };
            setTimeout(function () {
                showTxStepsDialog({
                    title: stepsTitle,
                    steps,
                    progressText,
                    interactive: flow.interactive,
                    onAllDone,
                    onClose: clearStepSecretsAndClose,
                });
            }, 0);
            return true;
        } catch (err: any) {
            showWarnAlert((err && err.message) ? String(err.message) : String(err));
            return false;
        } finally {
            hideWaitingBox();
        }
    };
    showTransactionReviewDialog(review);
}

// Throwing wrapper around a submit-IPC result: the tx-steps dialog surfaces
// the thrown message on the failed step row.
function requireTxHash(result: any): string {
    if (!result || !result.success || !result.txHash) {
        throw new Error((result && result.error) ? String(result.error) : (langJson.errors.transactionSubmissionFailed || "Transaction submission failed."));
    }
    return String(result.txHash);
}

function approveStep(label: string, tokenAddress: string, privateKey: string, publicKey: string, advancedSigningEnabled: boolean): TxStepDefinition {
    return {
        label,
        prepare: async () => estimateGasForContext({
            txKind: "approveToken",
            defaultGasLimit: APPROVE_DEFAULT_GAS,
            tokenAddress,
        }),
        run: async (gasLimit) => requireTxHash(await submitLiquidityApprove({
            ...chainPayload(),
            tokenAddress,
            privateKey,
            publicKey,
            gasLimit: gasLimit || APPROVE_DEFAULT_GAS,
            advancedSigningEnabled,
        })),
    };
}

// True when the router still needs an approval for `tokenAddress` to move
// `requiredWei` base units. On lookup failure the approve step is included
// defensively (a redundant approve is harmless; a missing one fails the flow).
async function needsRouterApproval(tokenAddress: string, requiredWei: bigint): Promise<boolean> {
    try {
        const res = await getLiquidityCheckAllowance({
            ...chainPayload(),
            tokenAddress,
            ownerAddress: walletStore.currentWalletAddress,
            requiredAmountWei: requiredWei.toString(),
        });
        if (res && res.success === true) return res.sufficient !== true;
    } catch {
        /* fall through */
    }
    return true;
}

// ---------------- Navigation ----------------

const ADVANCED_SCREEN_IDS = ["advancedScreen", "tokenCreateScreen", "poolsScreen", "liquidityScreen"];

// Full container switch (same set showSettingsScreen toggles): the Advanced
// hub is opened from the burger menu, so any top-level screen may be visible.
function showAdvancedChild(screenId: string): void {
    setHeaderBand("compact");
    byId("login-content").style.display = "none";
    byId("main-content").style.display = "none";
    byId("wallets-content").style.display = "none";
    byId("WalletsScreen").style.display = "none";
    byId("revealSeedScreen").style.display = "none";
    byId("backupSpecificWalletScreen").style.display = "none";
    byId("networkListScreen").style.display = "none";
    byId("releaseListScreen").style.display = "none";
    byId("releaseAddScreen").style.display = "none";
    byId("divNetworkDropdown").style.display = "none";
    byId("ValidatorScreen").style.display = "none";
    byId("settingsScreen").style.display = "none";

    byId("settings-content").style.display = "block";
    for (const id of ADVANCED_SCREEN_IDS) {
        byId(id).style.display = (id === screenId) ? "block" : "none";
    }
}

export function showAdvancedScreen(): boolean {
    showAdvancedChild("advancedScreen");
    return false;
}

export function showTokenCreateScreen(): boolean {
    showAdvancedChild("tokenCreateScreen");
    inputById("txtCreateTokenName").value = "";
    inputById("txtCreateTokenSymbol").value = "";
    selectById("ddlCreateTokenDecimals").value = "18";
    inputById("txtCreateTokenSupply").value = "";
    setInlineError("divCreateTokenError", null);
    resetCurrentGasConfig(createTokenGasState);
    setGasFeeLabel("spanCreateTokenGasFee", "");
    return false;
}

export function showPoolsScreen(): boolean {
    showAdvancedChild("poolsScreen");
    byId("divPoolsListPanel").style.display = "block";
    byId("divPoolsCreatePanel").style.display = "none";
    byId("divPoolsRefresh").style.display = "";
    void refreshPoolsTable();
    return false;
}

export function showPoolsCreatePanel(): boolean {
    byId("divPoolsListPanel").style.display = "none";
    byId("divPoolsCreatePanel").style.display = "block";
    // The refresh icon / spinner in the screen header only applies to the pool list.
    byId("divPoolsRefresh").style.display = "none";
    byId("divPoolsRefreshLoading").style.display = "none";
    populateTokenPicker("ddlPoolsTokenA");
    populateTokenPicker("ddlPoolsTokenB");
    selectById("ddlPoolsTokenA").value = "";
    selectById("ddlPoolsTokenB").value = "";
    setInlineError("divPoolsPairWarn", null);
    void updatePickerInfoRows("PoolsA", "");
    void updatePickerInfoRows("PoolsB", "");
    resetCurrentGasConfig(createPairGasState);
    setGasFeeLabel("spanCreatePairGasFee", "");
    return false;
}

export function showLiquidityScreen(): boolean {
    showAdvancedChild("liquidityScreen");
    void showLiquidityPositionsPanel();
    return false;
}

// Context-aware top-left back buttons: sub-panels step back to their parent
// panel first; the default view returns to the Advanced hub.
export function onPoolsBackClick(): boolean {
    if (byId("divPoolsCreatePanel").style.display !== "none") {
        return showPoolsScreen();
    }
    return showAdvancedScreen();
}

export function onLiquidityBackClick(): boolean {
    if (byId("divLiquidityPositionsPanel").style.display === "none") {
        void showLiquidityPositionsPanel();
        return false;
    }
    return showAdvancedScreen();
}

// ---------------- Pools ----------------

// In-memory caches survive screen navigation. Both lists remain available for
// 10 minutes and are rendered immediately while fresh RPC scans run in the
// background.
const POOLS_CACHE_TTL_MS = 10 * 60 * 1000;
const POSITIONS_CACHE_TTL_MS = 10 * 60 * 1000;
let poolsCache: { key: string; at: number; pools: LiquidityPairSnapshot[] } | null = null;
let positionsCache: { key: string; at: number; positions: LiquidityPositionSnapshot[] } | null = null;

// Cache key: chainId + active release factory (a release switch or network
// switch must never serve stale data).
function advancedCacheKey(): string {
    const net = networkStore.currentBlockchainNetwork as { networkId: number };
    const factory = (currentSwapRelease && currentSwapRelease.factory) ? String(currentSwapRelease.factory) : String(BUILTIN_SWAP_RELEASES[0].factory);
    return String(net.networkId) + "|" + factory.toLowerCase();
}

// Swap the header refresh icon for a spinner while a fetch is in flight
// (same pattern as the home screen's divRefreshBalance / divLoadingBalance).
function setRefreshSpinner(refreshId: string, loading: boolean): void {
    byId(refreshId).style.display = loading ? "none" : "";
    byId(refreshId + "Loading").style.display = loading ? "block" : "none";
}

let poolsRefreshToken = 0;

export async function refreshPoolsTable(): Promise<void> {
    if (!networkStore.currentBlockchainNetwork) return;
    const myToken = ++poolsRefreshToken;
    const key = advancedCacheKey();
    setInlineError("divPoolsListError", null);

    const cachedPools =
        poolsCache != null &&
        poolsCache.key === key &&
        (Date.now() - poolsCache.at) < POOLS_CACHE_TTL_MS
            ? poolsCache.pools
            : null;
    if (cachedPools != null) {
        renderPoolsTable(cachedPools);
    } else {
        byId("tbodyPoolsRow").textContent = "";
    }

    setRefreshSpinner("divPoolsRefresh", true);

    const res = await getLiquidityPools(chainPayload());
    if (myToken !== poolsRefreshToken) return;
    setRefreshSpinner("divPoolsRefresh", false);
    if (!res || !res.success || res.pools == null) {
        setInlineError("divPoolsListError", (res && res.error) ? String(res.error) : t("errors-generic", "Something went wrong."));
        return;
    }
    poolsCache = { key, at: Date.now(), pools: res.pools };
    renderPoolsTable(res.pools);
}

function renderPoolsTable(pools: LiquidityPairSnapshot[]): void {
    const tbody = byId("tbodyPoolsRow");
    tbody.textContent = "";
    if (pools.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 3;
        td.textContent = t("no-pools", "No pools yet.");
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }
    for (const pool of pools) {
        const tr = document.createElement("tr");

        const sym0 = pairTokenSymbol(pool.token0, pool.symbol0);
        const sym1 = pairTokenSymbol(pool.token1, pool.symbol1);

        const tdPair = document.createElement("td");
        tdPair.textContent = sym0 + " / " + sym1;
        tr.appendChild(tdPair);

        const tdReserves = document.createElement("td");
        tdReserves.textContent =
            formatBaseUnits(BigInt(pool.reserve0), pool.decimals0) + " " + sym0 + " + " +
            formatBaseUnits(BigInt(pool.reserve1), pool.decimals1) + " " + sym1;
        tr.appendChild(tdReserves);

        const tdAddr = document.createElement("td");
        tdAddr.appendChild(explorerAddressLink(pool.pairAddress));
        tr.appendChild(tdAddr);

        tbody.appendChild(tr);
    }
}

let poolsPairCheckToken = 0;

export async function onPoolsTokenChange(): Promise<void> {
    setInlineError("divPoolsPairWarn", null);
    const a = selectById("ddlPoolsTokenA").value;
    const b = selectById("ddlPoolsTokenB").value;
    void updatePickerInfoRows("PoolsA", a);
    void updatePickerInfoRows("PoolsB", b);
    scheduleCreatePairGas();
    if (!a || !b || a === b || !networkStore.currentBlockchainNetwork) return;
    const myToken = ++poolsPairCheckToken;
    const res = await getLiquidityPairInfo({ ...chainPayload(), tokenAValue: a, tokenBValue: b });
    if (myToken !== poolsPairCheckToken) return;
    if (res && res.success && res.exists) {
        setInlineError("divPoolsPairWarn", t("pair-exists-warn", "This pair already exists."));
    }
}

export async function onCreatePairClick(): Promise<void> {
    if (!networkStore.currentBlockchainNetwork) return;
    const a = selectById("ddlPoolsTokenA").value;
    const b = selectById("ddlPoolsTokenB").value;
    if (!a || !b) {
        setInlineError("divPoolsPairWarn", t("select-both-tokens", "Select both tokens."));
        return;
    }
    if (a === b) {
        setInlineError("divPoolsPairWarn", t("identical-tokens", "Select two different tokens."));
        return;
    }
    setInlineError("divPoolsPairWarn", null);

    showLoadingAndExecuteAsync(langJson.langValues.pleaseWait || "Please wait...", async function () {
        try {
            const info = await getLiquidityPairInfo({ ...chainPayload(), tokenAValue: a, tokenBValue: b });
            if (info && info.success && info.exists) {
                hideWaitingBox();
                setInlineError("divPoolsPairWarn", t("pair-exists-warn", "This pair already exists."));
                return;
            }
            const resolvedGas = resolveGasForTx(CREATE_PAIR_DEFAULT_GAS, createPairGasState);
            const gasLimit = parseInt(resolvedGas.gasLimit, 10);
            hideWaitingBox();
            const symA = tokenValueSymbol(a);
            const symB = tokenValueSymbol(b);
            const stepLabel = t("step-create-pair", "Create pair") + " " + symA + " / " + symB;
            const factoryAddress = currentSwapRelease
                ? currentSwapRelease.factory
                : BUILTIN_SWAP_RELEASES[0].factory;
            showReviewThenSteps({
                review: {
                    asset: t("create-pair", "Create Pair") + ": " + symA + " / " + symB,
                    contractAddress: factoryAddress,
                    toAddress: factoryAddress,
                    quantityLabelKey: "send-quantity",
                    quantityValue: "0",
                    gasLimit: resolvedGas.gasLimit,
                    gasFee: resolvedGas.gasFee,
                },
                stepsTitle: t("create-pair", "Create Pair"),
                buildSteps: (privateKey, publicKey, advancedSigningEnabled) => [{
                    label: stepLabel,
                    run: async () => requireTxHash(await submitPoolsCreatePair({
                        ...chainPayload(),
                        tokenAValue: a,
                        tokenBValue: b,
                        privateKey,
                        publicKey,
                        gasLimit,
                        advancedSigningEnabled,
                    })),
                }],
                onClose: () => {
                    void showPoolsScreen();
                },
            });
        } catch (err: any) {
            hideWaitingBox();
            showWarnAlert((err && err.message) ? String(err.message) : String(err));
        }
    });
}

// ---------------- Create token ----------------

export async function onCreateTokenClick(): Promise<void> {
    if (!networkStore.currentBlockchainNetwork) return;
    const name = (inputById("txtCreateTokenName").value || "").trim();
    const symbol = (inputById("txtCreateTokenSymbol").value || "").trim();
    const decimals = parseInt(selectById("ddlCreateTokenDecimals").value, 10);
    const supply = (inputById("txtCreateTokenSupply").value || "").trim();

    if (name.length < 1 || name.length > 48 || htmlEncode(name) !== name || containsUnsafeDisplayText(name)) {
        setInlineError("divCreateTokenError", t("token-name-invalid", "Enter a token name (up to 48 characters)."));
        return;
    }
    if (!/^[A-Za-z0-9]{1,16}$/.test(symbol)) {
        setInlineError("divCreateTokenError", t("token-symbol-invalid", "Symbol must be 1-16 letters or digits."));
        return;
    }
    // Same guard the wallet's token list applies: refuse to create tokens
    // that impersonate stablecoins / fiat currencies.
    if (impersonatesStablecoin(symbol, name)) {
        setInlineError("divCreateTokenError", t("token-impersonator", "This name or symbol is not allowed."));
        return;
    }
    if (!Number.isInteger(decimals) || decimals < 1 || decimals > 18) {
        setInlineError("divCreateTokenError", t("token-decimals-invalid", "Decimals must be between 1 and 18."));
        return;
    }
    let supplyBase: bigint;
    try {
        supplyBase = parseBaseUnits(supply, decimals);
    } catch {
        setInlineError("divCreateTokenError", t("token-supply-invalid", "Enter a valid total supply."));
        return;
    }
    if (supplyBase <= 0n) {
        setInlineError("divCreateTokenError", t("token-supply-invalid", "Enter a valid total supply."));
        return;
    }
    setInlineError("divCreateTokenError", null);

    const resolvedGas = resolveGasForTx(DEPLOY_TOKEN_DEFAULT_GAS, createTokenGasState);
    const gasLimit = parseInt(resolvedGas.gasLimit, 10);
    let deployedAddress: string | null = null;
    showReviewThenSteps({
        review: {
            asset: name + " (" + symbol + ")",
            assetLabelKey: "token-being-created",
            contractAddress: null,
            toAddress: null,
            quantityLabelKey: "token-total-supply",
            quantityValue: supply + " " + symbol,
            gasLimit: resolvedGas.gasLimit,
            gasFee: resolvedGas.gasFee,
        },
        stepsTitle: t("create-token-status", "Create Token Status"),
        progressText: t("create-token-progress", "Creating token."),
        buildSteps: (privateKey, publicKey, advancedSigningEnabled) => [{
            label: t("step-deploy-token", "Deploy token") + " " + symbol,
            run: async () => {
                const result = await submitTokenCreate({
                    ...chainPayload(),
                    name,
                    symbol,
                    decimals,
                    totalSupply: supply,
                    privateKey,
                    publicKey,
                    gasLimit,
                    advancedSigningEnabled,
                });
                const txHash = requireTxHash(result);
                deployedAddress = result.contractAddress ? String(result.contractAddress) : null;
                return txHash;
            },
        }],
        onAllDone: () => {
            if (deployedAddress == null) return null;
            const wrap = document.createElement("div");
            const header = document.createElement("div");
            header.style.display = "flex";
            header.style.alignItems = "center";
            header.style.justifyContent = "space-between";
            const label = document.createElement("label");
            label.style.fontWeight = "bold";
            label.textContent = t("token-contract-address", "Token contract address");
            header.appendChild(label);
            const buttons = document.createElement("div");
            buttons.style.display = "flex";
            buttons.style.alignItems = "center";
            buttons.style.gap = "12px";
            const copyBtn = document.createElement("div");
            copyBtn.className = "copy-container";
            copyBtn.setAttribute("role", "button");
            copyBtn.title = "Copy";
            copyBtn.addEventListener("click", function (event) {
                const el = event.currentTarget as HTMLElement;
                void WriteTextToClipboard(deployedAddress!).then(() => el.blur());
            });
            const scanBtn = document.createElement("div");
            scanBtn.className = "scan-container";
            scanBtn.setAttribute("role", "button");
            scanBtn.title = "Block Explorer";
            scanBtn.addEventListener("click", function (event) {
                const el = event.currentTarget as HTMLElement;
                void OpenScanAddress(deployedAddress!).then(() => el.blur());
            });
            buttons.appendChild(copyBtn);
            buttons.appendChild(scanBtn);
            header.appendChild(buttons);
            wrap.appendChild(header);
            const addr = document.createElement("p");
            addr.style.fontFamily = "monospace";
            addr.style.wordBreak = "break-all";
            addr.style.marginTop = "4px";
            addr.textContent = deployedAddress;
            wrap.appendChild(addr);
            return wrap;
        },
        onClose: () => { void showTokenCreateScreen(); },
    });
}

// ---------------- Liquidity: positions ----------------

let positionsRefreshToken = 0;

function showLiquidityPanel(panelId: string): void {
    for (const id of ["divLiquidityPositionsPanel", "divLiquidityAddPanel", "divLiquidityRemovePanel"]) {
        byId(id).style.display = (id === panelId) ? "block" : "none";
    }
}

export async function showLiquidityPositionsPanel(): Promise<void> {
    showLiquidityPanel("divLiquidityPositionsPanel");
    await refreshLiquidityPositions();
}

export async function refreshLiquidityPositions(): Promise<void> {
    if (!networkStore.currentBlockchainNetwork) return;
    const myToken = ++positionsRefreshToken;
    const key = advancedCacheKey() + "|" + String(walletStore.currentWalletAddress).toLowerCase();
    setInlineError("divLiquidityPositionsError", null);

    const cacheMatches = positionsCache != null && positionsCache.key === key;
    const cacheIsFresh = cacheMatches && (Date.now() - positionsCache!.at) < POSITIONS_CACHE_TTL_MS;
    const cachedPositions = cacheIsFresh
        ? positionsCache!.positions
        : null;
    if (cachedPositions != null) {
        // Stale-while-revalidate: keep the current list visible and refresh it
        // silently. The top-right spinner is the only loading indicator.
        renderLiquidityPositions(cachedPositions);
    } else {
        byId("divLiquidityPositionsList").textContent = "";
        byId("divLiquidityPositionsEmpty").style.display = "none";
    }

    // Every visit/explicit refresh revalidates in the background.
    setRefreshSpinner("divLiquidityPositionsRefresh", true);

    const res = await getLiquidityPositions({
        ...chainPayload(),
        ownerAddress: walletStore.currentWalletAddress,
    });
    if (myToken !== positionsRefreshToken) return;
    setRefreshSpinner("divLiquidityPositionsRefresh", false);
    if (!res || !res.success || res.positions == null) {
        setInlineError("divLiquidityPositionsError", (res && res.error) ? String(res.error) : t("errors-generic", "Something went wrong."));
        return;
    }
    positionsCache = { key, at: Date.now(), positions: res.positions };
    renderLiquidityPositions(res.positions);
}

function renderLiquidityPositions(positions: LiquidityPositionSnapshot[]): void {
    const empty = byId("divLiquidityPositionsEmpty");
    const list = byId("divLiquidityPositionsList");
    list.textContent = "";
    if (positions.length === 0) {
        empty.style.display = "block";
        return;
    }
    empty.style.display = "none";
    for (const position of positions) {
        list.appendChild(buildPositionCard(position));
    }
}

function buildPositionCard(position: LiquidityPositionSnapshot): HTMLElement {
    const lp = BigInt(position.lpBalance);
    const totalSupply = BigInt(position.totalSupply);
    const amount0 = positionUnderlying(lp, BigInt(position.reserve0), totalSupply);
    const amount1 = positionUnderlying(lp, BigInt(position.reserve1), totalSupply);
    const sym0 = pairTokenSymbol(position.token0, position.symbol0);
    const sym1 = pairTokenSymbol(position.token1, position.symbol1);
    const sharePct = poolSharePercent(lp, totalSupply);

    const card = document.createElement("div");
    card.style.padding = "8px 0";

    // Plain label styling (not "heading medium bold") so the card title reads
    // as a card label, clearly smaller than the "My Positions" section title.
    const title = document.createElement("div");
    title.style.fontWeight = "600";
    title.style.fontSize = "0.95em";
    title.textContent = sym0 + " / " + sym1;
    card.appendChild(title);

    const details = document.createElement("div");
    details.style.whiteSpace = "pre-line";
    details.textContent =
        t("lp-tokens", "LP tokens") + ": " + formatBaseUnits(lp, LP_TOKEN_DECIMALS) + "\n" +
        sym0 + ": " + formatBaseUnits(amount0, position.decimals0) + "\n" +
        sym1 + ": " + formatBaseUnits(amount1, position.decimals1) + "\n" +
        t("pool-share", "Pool share") + ": " + (sharePct < 0.01 ? "<0.01" : sharePct.toFixed(2)) + "%";
    card.appendChild(details);

    const actions = document.createElement("div");
    const addLink = document.createElement("a");
    addLink.href = "#";
    addLink.textContent = t("add", "Add");
    addLink.addEventListener("click", function (ev: Event) {
        ev.preventDefault();
        void showLiquidityAddPanel(position);
        return false;
    });
    actions.appendChild(addLink);
    actions.appendChild(document.createTextNode(" \u00a0 "));
    const removeLink = document.createElement("a");
    removeLink.href = "#";
    removeLink.textContent = t("remove", "Remove");
    removeLink.addEventListener("click", function (ev: Event) {
        ev.preventDefault();
        showLiquidityRemovePanel(position);
        return false;
    });
    actions.appendChild(removeLink);
    card.appendChild(actions);

    const divider = document.createElement("div");
    divider.className = "divider";
    card.appendChild(divider);
    return card;
}

// ---------------- Liquidity: add ----------------

let addPairInfo: LiquidityPairInfoResult | null = null;
let addPairInfoToken = 0;
let liquidityAutofillInProgress = false;

export async function showLiquidityAddPanel(position: LiquidityPositionSnapshot | null): Promise<void> {
    showLiquidityPanel("divLiquidityAddPanel");
    populateTokenPicker("ddlLiquidityTokenA");
    populateTokenPicker("ddlLiquidityTokenB");
    inputById("txtLiquidityAmountA").value = "";
    inputById("txtLiquidityAmountB").value = "";
    setInlineError("divLiquidityAddError", null);
    byId("divLiquidityFirstProviderWarn").style.display = "none";
    if (position != null) {
        // Prefill from the position card; tokens missing from the wallet's
        // token list simply stay unselected.
        setPickerValue("ddlLiquidityTokenA", pickerValueForTokenAddress(position.token0));
        setPickerValue("ddlLiquidityTokenB", pickerValueForTokenAddress(position.token1));
    }
    await onLiquidityTokenChange();
}

export async function onLiquidityTokenChange(): Promise<void> {
    addPairInfo = null;
    byId("divLiquidityFirstProviderWarn").style.display = "none";
    setInlineError("divLiquidityAddError", null);
    const a = selectById("ddlLiquidityTokenA").value;
    const b = selectById("ddlLiquidityTokenB").value;
    void updatePickerInfoRows("LiquidityA", a);
    void updatePickerInfoRows("LiquidityB", b);
    if (!a || !b || a === b || !networkStore.currentBlockchainNetwork) return;
    const myToken = ++addPairInfoToken;
    const res = await getLiquidityPairInfo({
        ...chainPayload(),
        tokenAValue: a,
        tokenBValue: b,
        ownerAddress: walletStore.currentWalletAddress,
    });
    if (myToken !== addPairInfoToken) return;
    if (!res || !res.success) return;
    addPairInfo = res;
    const empty = !res.exists || res.pair == null || BigInt(res.pair.reserve0) === 0n || BigInt(res.pair.reserve1) === 0n;
    byId("divLiquidityFirstProviderWarn").style.display = empty ? "block" : "none";
}

// Reserves oriented to the picker's A/B sides (pair storage order is token0 /
// token1). Null when the pair is missing or empty (no ratio to quote from).
function orientedAddReserves(): { reserveA: bigint; reserveB: bigint } | null {
    if (addPairInfo == null || !addPairInfo.exists || addPairInfo.pair == null || addPairInfo.tokenAAddress == null) return null;
    const pair = addPairInfo.pair;
    const reserve0 = BigInt(pair.reserve0);
    const reserve1 = BigInt(pair.reserve1);
    if (reserve0 === 0n || reserve1 === 0n) return null;
    const aIsToken0 = pair.token0.toLowerCase() === String(addPairInfo.tokenAAddress).toLowerCase();
    return aIsToken0 ? { reserveA: reserve0, reserveB: reserve1 } : { reserveA: reserve1, reserveB: reserve0 };
}

export function onLiquidityAmountInput(side: "A" | "B"): void {
    if (liquidityAutofillInProgress) return;
    sanitizeNumericInput(inputById(side === "A" ? "txtLiquidityAmountA" : "txtLiquidityAmountB"));
    const reserves = orientedAddReserves();
    if (reserves == null) return;
    const a = selectById("ddlLiquidityTokenA").value;
    const b = selectById("ddlLiquidityTokenB").value;
    if (!a || !b) return;
    const fromInput = inputById(side === "A" ? "txtLiquidityAmountA" : "txtLiquidityAmountB");
    const toInput = inputById(side === "A" ? "txtLiquidityAmountB" : "txtLiquidityAmountA");
    const fromDecimals = tokenValueDecimals(side === "A" ? a : b);
    const toDecimals = tokenValueDecimals(side === "A" ? b : a);
    const reserveFrom = side === "A" ? reserves.reserveA : reserves.reserveB;
    const reserveTo = side === "A" ? reserves.reserveB : reserves.reserveA;
    let amountWei: bigint;
    try {
        amountWei = parseBaseUnits((fromInput.value || "").trim(), fromDecimals);
    } catch {
        return; // partial / invalid input: leave the other side unchanged
    }
    const quoted = quote(amountWei, reserveFrom, reserveTo);
    liquidityAutofillInProgress = true;
    toInput.value = quoted > 0n ? formatBaseUnits(quoted, toDecimals, toDecimals) : "";
    liquidityAutofillInProgress = false;
}

export async function onAddLiquidityClick(): Promise<void> {
    if (!networkStore.currentBlockchainNetwork) return;
    const a = selectById("ddlLiquidityTokenA").value;
    const b = selectById("ddlLiquidityTokenB").value;
    if (!a || !b) {
        setInlineError("divLiquidityAddError", t("select-both-tokens", "Select both tokens."));
        return;
    }
    if (a === b) {
        setInlineError("divLiquidityAddError", t("identical-tokens", "Select two different tokens."));
        return;
    }
    const amountA = (inputById("txtLiquidityAmountA").value || "").trim();
    const amountB = (inputById("txtLiquidityAmountB").value || "").trim();
    const decimalsA = tokenValueDecimals(a);
    const decimalsB = tokenValueDecimals(b);
    let amountAWei: bigint;
    let amountBWei: bigint;
    try {
        amountAWei = parseBaseUnits(amountA, decimalsA);
        amountBWei = parseBaseUnits(amountB, decimalsB);
    } catch {
        setInlineError("divLiquidityAddError", t("amounts-invalid", "Enter valid amounts for both sides."));
        return;
    }
    if (amountAWei <= 0n || amountBWei <= 0n) {
        setInlineError("divLiquidityAddError", t("amounts-invalid", "Enter valid amounts for both sides."));
        return;
    }
    let slippagePercent = parseFloat(inputById("txtLiquiditySlippage").value);
    if (isNaN(slippagePercent) || slippagePercent < 0 || slippagePercent > 50) slippagePercent = 0.5;
    setInlineError("divLiquidityAddError", null);

    const symA = tokenValueSymbol(a);
    const symB = tokenValueSymbol(b);

    showLoadingAndExecuteAsync(langJson.langValues.pleaseWait || "Please wait...", async function () {
        try {
            // Fresh pair lookup: drives the first-provider gas default and the
            // approval checks below.
            const info = await getLiquidityPairInfo({ ...chainPayload(), tokenAValue: a, tokenBValue: b });
            const pairExists = !!(info && info.success && info.exists && info.pair != null && BigInt(info.pair.reserve0) > 0n);

            const approvals: { tokenAddress: string; label: string }[] = [];
            if (a !== "Q" && await needsRouterApproval(a, amountAWei)) {
                approvals.push({ tokenAddress: a, label: t("step-approve", "Approve") + " " + symA });
            }
            if (b !== "Q" && await needsRouterApproval(b, amountBWei)) {
                approvals.push({ tokenAddress: b, label: t("step-approve", "Approve") + " " + symB });
            }

            const defaultGas = pairExists ? ADD_LIQUIDITY_DEFAULT_GAS : CREATE_PAIR_DEFAULT_GAS;
            hideWaitingBox();

            const routerAddress = currentSwapRelease
                ? currentSwapRelease.router
                : BUILTIN_SWAP_RELEASES[0].router;
            showReviewThenSteps({
                review: {
                    asset: symA + " / " + symB,
                    assetLabelKey: "liquidity-pool",
                    contractAddress: routerAddress,
                    toAddress: routerAddress,
                    quantityLabelKey: "send-quantity",
                    quantityValue: amountA + " " + symA + " + " + amountB + " " + symB,
                },
                stepsTitle: t("add-liquidity", "Add Liquidity"),
                interactive: true,
                buildSteps: (privateKey, publicKey, advancedSigningEnabled) => {
                    const steps: TxStepDefinition[] = approvals.map((ap) =>
                        approveStep(ap.label, ap.tokenAddress, privateKey, publicKey, advancedSigningEnabled));
                    steps.push({
                        label: t("step-add-liquidity", "Add liquidity") + " " + symA + " / " + symB,
                        // This estimate runs only after all approval receipts
                        // succeeded, so the router follows its real add path.
                        prepare: async () => estimateGasForContext({
                            txKind: "addLiquidity",
                            defaultGasLimit: defaultGas,
                            tokenAValue: a,
                            tokenBValue: b,
                            amountA,
                            amountB,
                            decimalsA,
                            decimalsB,
                            slippagePercent,
                            ownerAddress: walletStore.currentWalletAddress,
                        }),
                        run: async (gasLimit) => requireTxHash(await submitLiquidityAdd({
                            ...chainPayload(),
                            tokenAValue: a,
                            tokenBValue: b,
                            amountA,
                            amountB,
                            decimalsA,
                            decimalsB,
                            slippagePercent,
                            ownerAddress: walletStore.currentWalletAddress,
                            privateKey,
                            publicKey,
                            gasLimit: gasLimit || defaultGas,
                            advancedSigningEnabled,
                        })),
                    });
                    return steps;
                },
                onAllDone: () => {
                    void refreshPoolsTable();
                },
                onClose: () => {
                    void showLiquidityPositionsPanel();
                },
            });
        } catch (err: any) {
            hideWaitingBox();
            showWarnAlert((err && err.message) ? String(err.message) : String(err));
        }
    });
}

// ---------------- Liquidity: remove ----------------

let removePosition: LiquidityPositionSnapshot | null = null;

export function showLiquidityRemovePanel(position: LiquidityPositionSnapshot): void {
    removePosition = position;
    showLiquidityPanel("divLiquidityRemovePanel");
    const sym0 = pairTokenSymbol(position.token0, position.symbol0);
    const sym1 = pairTokenSymbol(position.token1, position.symbol1);
    byId("divLiquidityRemovePair").textContent = sym0 + " / " + sym1;
    inputById("rngLiquidityRemovePercent").value = "50";
    inputById("txtLiquidityRemoveSlippage").value = "0.5";
    setInlineError("divLiquidityRemoveError", null);
    onRemovePercentChange();
}

function currentRemovePercent(): number {
    const p = parseInt(inputById("rngLiquidityRemovePercent").value, 10);
    return isNaN(p) ? 50 : Math.max(1, Math.min(100, p));
}

// Burned LP + estimated amounts out for the current slider position.
function computeRemoveEstimates(): { burnWei: bigint; amount0: bigint; amount1: bigint } | null {
    if (removePosition == null) return null;
    const lp = BigInt(removePosition.lpBalance);
    const totalSupply = BigInt(removePosition.totalSupply);
    const burnWei = percentOfAmount(lp, currentRemovePercent());
    return {
        burnWei,
        amount0: positionUnderlying(burnWei, BigInt(removePosition.reserve0), totalSupply),
        amount1: positionUnderlying(burnWei, BigInt(removePosition.reserve1), totalSupply),
    };
}

export function onRemovePercentChange(): void {
    if (removePosition == null) return;
    byId("spanLiquidityRemovePercent").textContent = currentRemovePercent() + "%";
    const est = computeRemoveEstimates();
    if (est == null) return;
    const sym0 = pairTokenSymbol(removePosition.token0, removePosition.symbol0);
    const sym1 = pairTokenSymbol(removePosition.token1, removePosition.symbol1);
    byId("divLiquidityRemoveEstimates").textContent =
        t("lp-to-burn", "LP tokens to burn") + ": " + formatBaseUnits(est.burnWei, LP_TOKEN_DECIMALS) + "\n" +
        t("estimated-out", "Estimated amounts out") + ":\n" +
        sym0 + ": " + formatBaseUnits(est.amount0, removePosition.decimals0) + "\n" +
        sym1 + ": " + formatBaseUnits(est.amount1, removePosition.decimals1);
}

export function setRemovePercentPreset(percent: number): void {
    inputById("rngLiquidityRemovePercent").value = String(percent);
    onRemovePercentChange();
}

export async function onRemoveLiquidityClick(): Promise<void> {
    if (removePosition == null || !networkStore.currentBlockchainNetwork) return;
    const position = removePosition;
    const est = computeRemoveEstimates();
    if (est == null || est.burnWei <= 0n) {
        setInlineError("divLiquidityRemoveError", t("amounts-invalid", "Enter valid amounts for both sides."));
        return;
    }
    let slippagePercent = parseFloat(inputById("txtLiquidityRemoveSlippage").value);
    if (isNaN(slippagePercent) || slippagePercent < 0 || slippagePercent > 50) slippagePercent = 0.5;
    setInlineError("divLiquidityRemoveError", null);

    const amount0Min = minWithSlippage(est.amount0, slippagePercent);
    const amount1Min = minWithSlippage(est.amount1, slippagePercent);
    const sym0 = pairTokenSymbol(position.token0, position.symbol0);
    const sym1 = pairTokenSymbol(position.token1, position.symbol1);

    showLoadingAndExecuteAsync(langJson.langValues.pleaseWait || "Please wait...", async function () {
        try {
            // The LP pair token itself must be approved toward the router.
            const needsLpApproval = await needsRouterApproval(position.pairAddress, est.burnWei);
            hideWaitingBox();

            const routerAddress = currentSwapRelease
                ? currentSwapRelease.router
                : BUILTIN_SWAP_RELEASES[0].router;
            showReviewThenSteps({
                review: {
                    asset: sym0 + " / " + sym1,
                    assetLabelKey: "liquidity-pool",
                    contractAddress: routerAddress,
                    toAddress: routerAddress,
                    quantityLabelKey: "lp-to-burn",
                    quantityValue: formatBaseUnits(est.burnWei, LP_TOKEN_DECIMALS) + " LP (" + currentRemovePercent() + "%)",
                },
                stepsTitle: t("remove-liquidity", "Remove Liquidity"),
                interactive: true,
                buildSteps: (privateKey, publicKey, advancedSigningEnabled) => {
                    const steps: TxStepDefinition[] = [];
                    if (needsLpApproval) {
                        steps.push(approveStep(
                            t("step-approve", "Approve") + " " + sym0 + "/" + sym1 + " LP",
                            position.pairAddress, privateKey, publicKey, advancedSigningEnabled));
                    }
                    steps.push({
                        label: t("step-remove-liquidity", "Remove liquidity") + " " + sym0 + " / " + sym1,
                        prepare: async () => estimateGasForContext({
                            txKind: "removeLiquidity",
                            defaultGasLimit: REMOVE_LIQUIDITY_DEFAULT_GAS,
                            tokenAAddress: position.token0,
                            tokenBAddress: position.token1,
                            liquidityWei: est.burnWei.toString(),
                            amountAMinWei: amount0Min.toString(),
                            amountBMinWei: amount1Min.toString(),
                            ownerAddress: walletStore.currentWalletAddress,
                        }),
                        run: async (gasLimit) => requireTxHash(await submitLiquidityRemove({
                            ...chainPayload(),
                            tokenAAddress: position.token0,
                            tokenBAddress: position.token1,
                            liquidityWei: est.burnWei.toString(),
                            amountAMinWei: amount0Min.toString(),
                            amountBMinWei: amount1Min.toString(),
                            ownerAddress: walletStore.currentWalletAddress,
                            privateKey,
                            publicKey,
                            gasLimit: gasLimit || REMOVE_LIQUIDITY_DEFAULT_GAS,
                            advancedSigningEnabled,
                        })),
                    });
                    return steps;
                },
                onAllDone: () => {
                    void refreshPoolsTable();
                },
                onClose: () => {
                    void showLiquidityPositionsPanel();
                },
            });
        } catch (err: any) {
            hideWaitingBox();
            showWarnAlert((err && err.message) ? String(err.message) : String(err));
        }
    });
}
