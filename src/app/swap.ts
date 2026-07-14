// Swap screen logic (quotes, allowances, execution, success panel).
// 1:1 port of the swap section of the old src/js/app.js.
import {
    getSwapCheckAllowance,
    getSwapCheckPairExists,
    getSwapQuoteAmountsIn,
    getSwapQuoteAmountsOut,
    OpenUrl,
    submitSwapAddAllowance,
    submitSwapRemoveAllowance,
    submitSwapSwap,
    weiToEtherFormatted,
    WriteTextToClipboard,
} from "../lib/bridge";
import { htmlEncode } from "../lib/util";
import { langJson } from "../lib/i18n";
import { walletGetByAddress, Wallet } from "../lib/wallet";
import {
    App,
    ADDRESS_TEMPLATE,
    BLOCK_EXPLORER_ACCOUNT_TEMPLATE,
    BLOCK_EXPLORER_DOMAIN_TEMPLATE,
    QuantumCoin,
    TxContext,
    byId,
    inputById,
    selectById,
    zero_address,
} from "./state";
import {
    APPROVE_DEFAULT_GAS,
    SWAP_DEFAULT_GAS,
    SWAP_GAS_FEE_RATE,
    formatGasFeeQ,
    onGasIconClick,
    resetCurrentGasConfig,
    resolveGasForTx,
    scheduleGasEstimation,
    setGasFeeLabel,
    swapApproveGasState,
} from "./gas";
import { advancedSigningGetDefaultValue } from "./settings";
import {
    closeTransactionReviewDialog,
    hideWaitingBox,
    showAlertAndExecuteOnClose,
    showLoadingAndExecuteAsync,
    showTransactionReviewDialog,
    showWarnAlert,
    txReviewNetworkText,
    TransactionReview,
} from "./dialog";
import { getGenericError, refreshAccountBalance, removeOptions, setHeaderBand, showWalletScreen } from "./app";
import { showSendCompletedDialog } from "./send";

export const SWAP_SHOW_NATIVE_COIN = false;

export function getSwapSymbolFromValue(value: string): string {
    if (!value || value === "Q") return "Q";
    if (App.currentWalletTokenList == null) return "Q";
    for (let i = 0; i < App.currentWalletTokenList.length; i++) {
        if (App.currentWalletTokenList[i].contractAddress === value) {
            return App.currentWalletTokenList[i].symbol || "Q";
        }
    }
    return "Q";
}

export async function getSwapBalanceForSymbol(value: string): Promise<string> {
    if (!value) return "0";
    if (value === "Q" && App.currentAccountDetails != null) {
        return await weiToEtherFormatted(App.currentAccountDetails.balance);
    }
    if (App.currentWalletTokenList == null) return "0";
    for (let i = 0; i < App.currentWalletTokenList.length; i++) {
        if (App.currentWalletTokenList[i].contractAddress === value) {
            return App.currentWalletTokenList[i].tokenBalance || "0";
        }
    }
    return "0";
}

export function getSwapContractAddress(value: string): string {
    return (!value || value === "Q") ? zero_address : value;
}

export function updateSwapContractLabels(): void {
    const fromValue = selectById("ddlSwapFromToken").value;
    const toValue = selectById("ddlSwapToToken").value;
    const showFromContract = fromValue && fromValue !== "Q";
    const showToContract = toValue && toValue !== "Q";
    byId("divSwapFromContractRow").style.display = showFromContract ? "flex" : "none";
    byId("divSwapToContractRow").style.display = showToContract ? "flex" : "none";
    const explorerBase = App.currentBlockchainNetwork ? BLOCK_EXPLORER_ACCOUNT_TEMPLATE.replace(BLOCK_EXPLORER_DOMAIN_TEMPLATE, App.currentBlockchainNetwork.blockExplorerDomain) : "";
    if (showFromContract) {
        const fromAddr = fromValue;
        const aFrom = byId<HTMLAnchorElement>("aSwapFromContract");
        aFrom.textContent = fromAddr;
        aFrom.setAttribute("data-contract-address", fromAddr);
        aFrom.href = explorerBase.replace(ADDRESS_TEMPLATE, fromAddr);
    }
    if (showToContract) {
        const toAddr = toValue;
        const aTo = byId<HTMLAnchorElement>("aSwapToContract");
        aTo.textContent = toAddr;
        aTo.setAttribute("data-contract-address", toAddr);
        aTo.href = explorerBase.replace(ADDRESS_TEMPLATE, toAddr);
    }
}

export async function openSwapFromContractInExplorer(): Promise<void> {
    const addr = byId("aSwapFromContract").getAttribute("data-contract-address") || getSwapContractAddress(selectById("ddlSwapFromToken").value);
    const url = BLOCK_EXPLORER_ACCOUNT_TEMPLATE.replace(BLOCK_EXPLORER_DOMAIN_TEMPLATE, (App.currentBlockchainNetwork as { blockExplorerDomain: string }).blockExplorerDomain).replace(ADDRESS_TEMPLATE, addr);
    await OpenUrl(url);
}

export async function openSwapToContractInExplorer(): Promise<void> {
    const addr = byId("aSwapToContract").getAttribute("data-contract-address") || getSwapContractAddress(selectById("ddlSwapToToken").value);
    const url = BLOCK_EXPLORER_ACCOUNT_TEMPLATE.replace(BLOCK_EXPLORER_DOMAIN_TEMPLATE, (App.currentBlockchainNetwork as { blockExplorerDomain: string }).blockExplorerDomain).replace(ADDRESS_TEMPLATE, addr);
    await OpenUrl(url);
}

export async function copySwapFromContractAddress(): Promise<void> {
    const addr = getSwapContractAddress(selectById("ddlSwapFromToken").value);
    await WriteTextToClipboard(addr);
}

export async function copySwapToContractAddress(): Promise<void> {
    const addr = getSwapContractAddress(selectById("ddlSwapToToken").value);
    await WriteTextToClipboard(addr);
}

export function formatTokenAmount(weiStr: string | null | undefined, decimals: unknown): string {
    if (!weiStr || String(weiStr).trim() === "" || weiStr === "0") return "0";
    const d = Math.max(0, parseInt(String(decimals), 10) || 18);
    const div = Math.pow(10, d);
    const big = BigInt(String(weiStr).trim());
    const divBig = BigInt(div);
    const intPart = big / divBig;
    const fracPart = big % divBig;
    const fracStr = fracPart.toString().padStart(d, "0").replace(/0+$/, "");
    if (fracStr === "") return intPart.toString();
    return intPart.toString() + "." + fracStr;
}

export async function updateSwapFromAllowanceDisplay(): Promise<void> {
    const row = byId("divSwapFromAllowanceRow");
    const span = byId("spanSwapFromAllowance");
    if (!row || !span) return;
    const fromValue = selectById("ddlSwapFromToken").value;
    if (!fromValue || !App.currentBlockchainNetwork) {
        row.style.display = "none";
        return;
    }
    try {
        const allowancePayload = {
            rpcEndpoint: App.currentBlockchainNetwork.rpcEndpoint,
            chainId: parseInt(String(App.currentBlockchainNetwork.networkId), 10),
            fromTokenValue: fromValue,
            ownerAddress: App.currentWalletAddress,
            requiredAmount: "0",
            fromDecimals: getSwapTokenDecimals(fromValue),
        };
        const result = await getSwapCheckAllowance(allowancePayload);
        if (!result || !result.success || !result.allowance) {
            row.style.display = "none";
            return;
        }
        const allowanceWei = String(result.allowance).trim();
        if (allowanceWei === "" || allowanceWei === "0" || BigInt(allowanceWei) === BigInt(0)) {
            row.style.display = "none";
            return;
        }
        const decimals = getSwapTokenDecimals(fromValue);
        span.textContent = formatTokenAmount(allowanceWei, decimals);
        row.style.display = "block";
    } catch {
        row.style.display = "none";
    }
}

export async function updateSwapBalanceLabels(): Promise<void> {
    const fromSymbol = selectById("ddlSwapFromToken").value;
    const toSymbol = selectById("ddlSwapToToken").value;
    const fromBal = await getSwapBalanceForSymbol(fromSymbol);
    const toBal = await getSwapBalanceForSymbol(toSymbol);
    byId("spanSwapFromBalance").textContent = fromBal;
    byId("spanSwapToBalance").textContent = toBal;
    updateSwapContractLabels();
    await updateSwapFromAllowanceDisplay();
}

export function normalizeAmountForNumberInput(value: unknown): string {
    if (value == null || value === "") return "";
    return String(value).replace(/,/g, "").trim();
}

export function setSwapFromQuantityToBalance(): boolean {
    (async function () {
        const fromSymbol = selectById("ddlSwapFromToken").value;
        const bal = await getSwapBalanceForSymbol(fromSymbol);
        inputById("txtSwapFromQuantity").value = normalizeAmountForNumberInput(bal);
        updateToQuantityFromFrom();
    })();
    return false;
}

export function setSwapToQuantityToBalance(): boolean {
    (async function () {
        const toSymbol = selectById("ddlSwapToToken").value;
        const bal = await getSwapBalanceForSymbol(toSymbol);
        inputById("txtSwapToQuantity").value = normalizeAmountForNumberInput(bal);
        updateFromQuantityFromTo();
    })();
    return false;
}

export function getSwapDropdownDisplayText(tokenName: string, tokenSymbol: string, contractAddress: string): string {
    const namePart = (tokenName || "").substring(0, 25);
    const symbolPart = (tokenSymbol || "").substring(0, 6);
    if (!contractAddress || contractAddress === zero_address) {
        return namePart + " (" + symbolPart + ")";
    }
    const addr = contractAddress;
    const addrPart = addr.length >= 10 ? addr.substring(0, 5) + "..." + addr.slice(-5) : addr;
    return namePart + " (" + symbolPart + ") " + addrPart;
}

export function getSwapTokenListFromWallet(): { value: string; displayText: string }[] {
    const list: { value: string; displayText: string }[] = [];
    if (SWAP_SHOW_NATIVE_COIN) {
        list.push({ value: "Q", displayText: QuantumCoin + " (Q)" });
    }
    if (App.currentWalletTokenList != null && App.currentWalletTokenList.length > 0) {
        for (let i = 0; i < App.currentWalletTokenList.length; i++) {
            const t = App.currentWalletTokenList[i];
            if (!t.symbol || !t.name || !t.contractAddress) continue;
            if (htmlEncode(t.name) !== t.name || htmlEncode(t.symbol) !== t.symbol) continue;
            list.push({
                value: t.contractAddress,
                displayText: getSwapDropdownDisplayText(t.name, t.symbol, t.contractAddress),
            });
        }
    }
    return list;
}

export function populateSwapTokenDropdowns(): void {
    const swapTokenList = getSwapTokenListFromWallet();
    const ddlFrom = selectById("ddlSwapFromToken");
    const ddlTo = selectById("ddlSwapToToken");
    removeOptions(ddlFrom);
    removeOptions(ddlTo);
    const selectTokenText = (langJson && langJson.langValues && langJson.langValues["select-token"]) ? langJson.langValues["select-token"] : "Select token";
    const optFromPlaceholder = document.createElement("option");
    optFromPlaceholder.value = "";
    optFromPlaceholder.text = selectTokenText;
    ddlFrom.add(optFromPlaceholder);
    const optToPlaceholder = document.createElement("option");
    optToPlaceholder.value = "";
    optToPlaceholder.text = selectTokenText;
    ddlTo.add(optToPlaceholder);
    for (let i = 0; i < swapTokenList.length; i++) {
        const optFrom = document.createElement("option");
        optFrom.text = swapTokenList[i].displayText;
        optFrom.value = swapTokenList[i].value;
        ddlFrom.add(optFrom);
        const optTo = document.createElement("option");
        optTo.text = swapTokenList[i].displayText;
        optTo.value = swapTokenList[i].value;
        ddlTo.add(optTo);
    }
    ddlFrom.selectedIndex = 0;
    ddlTo.selectedIndex = 0;
    updateSwapTokenSymbolCache();
}

let swapTokenSymbolCache: Record<string, string> = {};

export function updateSwapTokenSymbolCache(): void {
    swapTokenSymbolCache = { "Q": "Q" };
    if (App.currentWalletTokenList != null) {
        for (let i = 0; i < App.currentWalletTokenList.length; i++) {
            const t = App.currentWalletTokenList[i];
            if (t.contractAddress && t.symbol) swapTokenSymbolCache[t.contractAddress] = t.symbol;
        }
    }
}

export function getSwapCachedSymbol(value: string): string {
    if (!value || value === "Q") return "Q";
    return swapTokenSymbolCache[value] != null ? swapTokenSymbolCache[value] : getSwapSymbolFromValue(value);
}

let swapQuantityUpdating = false;
let swapQuoteFromDebounceId: ReturnType<typeof setTimeout> | null = null;
let swapLastChanged: "from" | "to" = "from"; // which quantity the user last edited
let swapQuoteToDebounceId: ReturnType<typeof setTimeout> | null = null;
const SWAP_QUOTE_DEBOUNCE_MS = 400;

export function getSwapTokenDecimals(value: string | null): number {
    if (!value || value === "Q") return 18;
    if (App.currentWalletTokenList != null) {
        for (let i = 0; i < App.currentWalletTokenList.length; i++) {
            const token = App.currentWalletTokenList[i] as { contractAddress: string; decimals?: number };
            if (token.contractAddress === value && token.decimals != null) {
                return token.decimals;
            }
        }
    }
    return 18;
}

export function showSwapQuoteLoading(show: boolean): void {
    const el = byId("divSwapQuoteLoading");
    if (el) el.style.display = show ? "block" : "none";
}

export async function updateToQuantityFromFrom(): Promise<void> {
    if (swapQuantityUpdating) return;
    swapLastChanged = "from";
    const fromValue = selectById("ddlSwapFromToken").value;
    const toValue = selectById("ddlSwapToToken").value;
    const fromQtyStr = (inputById("txtSwapFromQuantity").value || "").trim();
    const fromQty = parseFloat(fromQtyStr);

    if (!fromQtyStr || isNaN(fromQty) || fromQty < 0) {
        inputById("txtSwapToQuantity").value = "";
        return;
    }
    if (!fromValue || !toValue || fromValue === toValue) {
        inputById("txtSwapToQuantity").value = "";
        return;
    }
    if (!App.currentBlockchainNetwork) return;

    swapQuantityUpdating = true;
    showSwapQuoteLoading(true);
    try {
        const payload = {
            rpcEndpoint: App.currentBlockchainNetwork.rpcEndpoint,
            chainId: parseInt(String(App.currentBlockchainNetwork.networkId), 10) || 123123,
            amountIn: fromQtyStr,
            fromTokenValue: fromValue,
            toTokenValue: toValue,
            fromDecimals: getSwapTokenDecimals(fromValue),
            toDecimals: getSwapTokenDecimals(toValue),
        };
        const result = await getSwapQuoteAmountsOut(payload);
        if (result && result.success && result.amountOut != null) {
            const outStr = String(result.amountOut).replace(/\.?0+$/, "") || result.amountOut;
            inputById("txtSwapToQuantity").value = outStr;
        } else {
            inputById("txtSwapToQuantity").value = "";
            if (result && !result.success && result.error) {
                showWarnAlert(result.error);
            }
        }
    } catch (e: any) {
        inputById("txtSwapToQuantity").value = "";
        showWarnAlert((e && e.message) ? e.message : String(e));
    } finally {
        showSwapQuoteLoading(false);
        swapQuantityUpdating = false;
    }
}

export function debouncedUpdateToQuantityFromFrom(): void {
    if (swapQuoteFromDebounceId != null) clearTimeout(swapQuoteFromDebounceId);
    swapQuoteFromDebounceId = setTimeout(function () {
        swapQuoteFromDebounceId = null;
        updateToQuantityFromFrom();
    }, SWAP_QUOTE_DEBOUNCE_MS);
}

export async function updateFromQuantityFromTo(): Promise<void> {
    if (swapQuantityUpdating) return;
    swapLastChanged = "to";
    const fromValue = selectById("ddlSwapFromToken").value;
    const toValue = selectById("ddlSwapToToken").value;
    const toQtyStr = (inputById("txtSwapToQuantity").value || "").trim();
    const toQty = parseFloat(toQtyStr);

    if (!toQtyStr || isNaN(toQty) || toQty < 0) {
        inputById("txtSwapFromQuantity").value = "";
        return;
    }
    if (!fromValue || !toValue || fromValue === toValue) {
        inputById("txtSwapFromQuantity").value = "";
        return;
    }
    if (!App.currentBlockchainNetwork) return;

    swapQuantityUpdating = true;
    showSwapQuoteLoading(true);
    try {
        const payload = {
            rpcEndpoint: App.currentBlockchainNetwork.rpcEndpoint,
            chainId: parseInt(String(App.currentBlockchainNetwork.networkId), 10),
            amountOut: toQtyStr,
            fromTokenValue: fromValue,
            toTokenValue: toValue,
            fromDecimals: getSwapTokenDecimals(fromValue),
            toDecimals: getSwapTokenDecimals(toValue),
        };
        const result = await getSwapQuoteAmountsIn(payload);
        if (result && result.success && result.amountIn != null) {
            const inStr = String(result.amountIn).replace(/\.?0+$/, "") || result.amountIn;
            inputById("txtSwapFromQuantity").value = inStr;
        } else {
            inputById("txtSwapFromQuantity").value = "";
            if (result && !result.success && result.error) {
                showWarnAlert(result.error);
            }
        }
    } catch (e: any) {
        inputById("txtSwapFromQuantity").value = "";
        showWarnAlert((e && e.message) ? e.message : String(e));
    } finally {
        showSwapQuoteLoading(false);
        swapQuantityUpdating = false;
    }
}

export function debouncedUpdateFromQuantityFromTo(): void {
    if (swapQuoteToDebounceId != null) clearTimeout(swapQuoteToDebounceId);
    swapQuoteToDebounceId = setTimeout(function () {
        swapQuoteToDebounceId = null;
        updateFromQuantityFromTo();
    }, SWAP_QUOTE_DEBOUNCE_MS);
}

export async function updateSwapScreenInfo(): Promise<boolean> {
    // Runs when either "from" or "to" token dropdown is changed. Check pair and show same error if pair doesn't exist.
    inputById("txtSwapFromQuantity").value = "";
    inputById("txtSwapToQuantity").value = "";
    updateSwapBalanceLabels();
    const fromValue = selectById("ddlSwapFromToken").value;
    const toValue = selectById("ddlSwapToToken").value;
    if (!fromValue || !toValue || fromValue === toValue) {
        return false;
    }
    if (!App.currentBlockchainNetwork) return false;
    let pairExists = false;
    try {
        const payload = {
            rpcEndpoint: App.currentBlockchainNetwork.rpcEndpoint,
            chainId: parseInt(String(App.currentBlockchainNetwork.networkId), 10) || 123123,
            fromTokenValue: fromValue,
            toTokenValue: toValue,
        };
        const result = await getSwapCheckPairExists(payload);
        pairExists = result && result.exists === true;
        if (!pairExists) {
            if (result && result.error) {
                showWarnAlert(result.error);
            } else {
                showWarnAlert((langJson && langJson.langValues && langJson.langValues["swap-no-pair"]) || "No pair has been created for these two tokens");
            }
            inputById("txtSwapToQuantity").value = "";
        }
    } catch (e: any) {
        showWarnAlert((e && e.message) ? e.message : String(e));
        inputById("txtSwapToQuantity").value = "";
    }
    if (pairExists) {
        updateToQuantityFromFrom();
    }
    resetCurrentGasConfig();
    setGasFeeLabel("spanSwapGasFee", "");
    scheduleSwapExecuteGasEstimation("divSwapGasIcon", "spanSwapGasFee");
    return false;
}

export function openSwapScreen(): boolean {
    byId("divNetworkDropdown").style.display = "none";
    byId("HomeScreen").style.display = "none";
    byId("SendScreen").style.display = "none";
    byId("OfflineSignScreen").style.display = "none";
    byId("SwapScreen").style.display = "block";
    byId("ReceiveScreen").style.display = "none";
    byId("TransactionsScreen").style.display = "none";
    setHeaderBand("compact");

    byId("divSwapScreenInner").style.display = "block";
    byId("divSwapConfirmPanel").style.display = "none";
    byId("divSwapRemoveAllowancePanel").style.display = "none";
    byId("divSwapAddAllowancePanel").style.display = "none";
    populateSwapTokenDropdowns();
    inputById("txtSwapFromQuantity").value = "";
    inputById("txtSwapToQuantity").value = "";
    inputById("txtSwapFromQuantity").focus();
    updateSwapBalanceLabels();
    resetCurrentGasConfig();
    setGasFeeLabel("spanSwapGasFee", "");
    attachSwapGasListeners();
    scheduleSwapExecuteGasEstimation("divSwapGasIcon", "spanSwapGasFee");
    return false;
}

export function attachSwapGasListeners(): void {
    const fromQty = inputById("txtSwapFromQuantity");
    const toQty = inputById("txtSwapToQuantity");
    if (fromQty && !fromQty.dataset.gasBound) { fromQty.addEventListener("input", function () { scheduleSwapExecuteGasEstimation("divSwapGasIcon", "spanSwapGasFee"); }); fromQty.dataset.gasBound = "1"; }
    if (toQty && !toQty.dataset.gasBound) { toQty.addEventListener("input", function () { scheduleSwapExecuteGasEstimation("divSwapGasIcon", "spanSwapGasFee"); }); toQty.dataset.gasBound = "1"; }
}

export function getSwapExecuteTxContext(): TxContext | null {
    const fromValue = selectById("ddlSwapFromToken").value;
    const toValue = selectById("ddlSwapToToken").value;
    const fromQty = (inputById("txtSwapFromQuantity").value || "").trim();
    const toQty = (inputById("txtSwapToQuantity").value || "").trim();
    if (!fromValue || !toValue || !fromQty || !toQty) return null;
    return {
        txKind: "swap",
        fromTokenValue: fromValue,
        toTokenValue: toValue,
        amountIn: fromQty,
        amountOut: toQty,
        lastChanged: swapLastChanged || "from",
        slippagePercent: parseFloat(inputById("txtSwapSlippage").value) || 1,
        fromDecimals: getSwapTokenDecimals(fromValue),
        toDecimals: getSwapTokenDecimals(toValue),
        recipientAddress: App.currentWalletAddress,
        defaultGasLimit: SWAP_DEFAULT_GAS,
    };
}

export function getSwapApproveTxContext(amount: string): TxContext | null {
    const fromValue = selectById("ddlSwapFromToken").value;
    if (!fromValue) return null;
    return {
        txKind: "approve",
        fromTokenValue: fromValue,
        amount: amount,
        fromDecimals: getSwapTokenDecimals(fromValue),
        defaultGasLimit: APPROVE_DEFAULT_GAS,
    };
}

export function onSwapGasIconClick(): boolean {
    return onGasIconClick("spanSwapGasFee", null, getSwapExecuteTxContext);
}

export function onSwapConfirmGasIconClick(): boolean {
    return onGasIconClick("spanSwapConfirmGasFee", null, getSwapExecuteTxContext);
}

export function onRemoveAllowanceGasIconClick(): boolean {
    return onGasIconClick("spanRemoveAllowanceGasFee", swapApproveGasState, function () { return getSwapApproveTxContext("0"); });
}

export function onAddAllowanceGasIconClick(): boolean {
    return onGasIconClick("spanAddAllowanceGasFee", swapApproveGasState, function () {
        const amt = (inputById("txtAddAllowanceQuantity").value || "").trim();
        if (!amt) return null;
        return getSwapApproveTxContext(amt);
    });
}

export function scheduleSwapExecuteGasEstimation(iconId: string, labelId: string): void {
    scheduleGasEstimation(getSwapExecuteTxContext, iconId, labelId);
}

export function setSwapConfirmPanelLoading(show: boolean): void {
    const loadingEl = byId("divSwapConfirmLoading");
    const backEl = byId("divBackSwapScreen");
    const slippageInput = inputById("txtSwapSlippage");
    const btnNext = byId<HTMLButtonElement>("btnSwapConfirmNext");
    if (loadingEl) loadingEl.style.display = show ? "block" : "none";
    const disabled = !!show;
    if (backEl) { backEl.style.pointerEvents = disabled ? "none" : ""; backEl.setAttribute("aria-disabled", disabled ? "true" : "false"); }
    if (slippageInput) slippageInput.disabled = disabled;
    if (btnNext) { btnNext.disabled = disabled; btnNext.style.pointerEvents = disabled ? "none" : ""; }
}

export async function onSwapNextClick(): Promise<boolean> {
    const fromValue = selectById("ddlSwapFromToken").value;
    const toValue = selectById("ddlSwapToToken").value;
    const fromQty = (inputById("txtSwapFromQuantity").value || "").trim();
    const toQty = (inputById("txtSwapToQuantity").value || "").trim();
    if (!fromQty || parseFloat(fromQty) <= 0) {
        showWarnAlert((langJson.langValues["swap-from-quantity"] || "From quantity") + " " + (langJson.errors && langJson.errors.invalidValue ? langJson.errors.invalidValue : "is required"));
        return false;
    }
    if (!toQty || parseFloat(toQty) <= 0) {
        showWarnAlert((langJson.langValues["swap-to-quantity"] || "To quantity") + " " + (langJson.errors && langJson.errors.invalidValue ? langJson.errors.invalidValue : "is required"));
        return false;
    }
    if (!fromValue || !toValue || fromValue === toValue) {
        showWarnAlert((langJson && langJson.langValues && langJson.langValues["swap-no-pair"]));
        return false;
    }
    if (!App.currentBlockchainNetwork) return false;
    let pairExists = false;
    try {
        const payload = {
            rpcEndpoint: App.currentBlockchainNetwork.rpcEndpoint,
            chainId: parseInt(String(App.currentBlockchainNetwork.networkId), 10),
            fromTokenValue: fromValue,
            toTokenValue: toValue,
        };
        const result = await getSwapCheckPairExists(payload);
        pairExists = result && result.exists === true;
        if (!pairExists) {
            if (result && result.error) {
                showWarnAlert(result.error);
            } else {
                showWarnAlert((langJson && langJson.langValues && langJson.langValues["swap-no-pair"]));
            }
            return false;
        }
    } catch (e: any) {
        showWarnAlert((e && e.message) ? e.message : String(e));
        return false;
    }
    byId("divSwapScreenInner").style.display = "none";
    setSwapConfirmPanelLoading(true);
    try {
        const allowancePayload = {
            rpcEndpoint: App.currentBlockchainNetwork.rpcEndpoint,
            chainId: parseInt(String(App.currentBlockchainNetwork.networkId), 10),
            fromTokenValue: fromValue,
            ownerAddress: App.currentWalletAddress,
            requiredAmount: fromQty,
            fromDecimals: getSwapTokenDecimals(fromValue),
        };
        const allowanceResult = await getSwapCheckAllowance(allowancePayload);
        if (!allowanceResult || !allowanceResult.success) {
            showWarnAlert((allowanceResult && allowanceResult.error) ? allowanceResult.error : "Failed to check approval");
            setSwapConfirmPanelLoading(false);
            byId("divSwapScreenInner").style.display = "block";
            return false;
        }
        if (allowanceResult.sufficient) {
            swapSuccessFromToken = fromValue;
            swapSuccessToToken = toValue;
            swapSuccessFromBefore = await getSwapBalanceForSymbol(fromValue);
            swapSuccessToBefore = await getSwapBalanceForSymbol(toValue);
            byId("divSwapConfirmPanel").style.display = "block";
            byId("divSwapRemoveAllowancePanel").style.display = "none";
            byId("divSwapAddAllowancePanel").style.display = "none";
            inputById("txtSwapSlippage").value = "1";
            const slippageRow = byId("divSwapSlippageRow");
            const btnConfirmNext = byId("btnSwapConfirmNext");
            slippageRow.style.display = "block";
            btnConfirmNext.textContent = (langJson && langJson.langValues && langJson.langValues["swap"]) ? langJson.langValues["swap"] : "Swap";
            // Refresh the gas estimate for the confirm panel using the common gas flow.
            resetCurrentGasConfig();
            setGasFeeLabel("spanSwapConfirmGasFee", "");
            scheduleSwapExecuteGasEstimation("divSwapConfirmGasIcon", "spanSwapConfirmGasFee");
        } else {
            showAddAllowancePanel(fromValue, fromQty);
        }
    } catch (e: any) {
        showWarnAlert((e && e.message) ? e.message : String(e));
        byId("divSwapScreenInner").style.display = "block";
    }
    setSwapConfirmPanelLoading(false);
    return false;
}

export function showAddAllowancePanel(fromValue: string, fromQty: string): void {
    byId("divSwapConfirmPanel").style.display = "none";
    byId("divSwapRemoveAllowancePanel").style.display = "none";
    byId("divSwapAddAllowancePanel").style.display = "block";
    const contractAddr = getSwapContractAddress(fromValue);
    const aEl = byId("aAddAllowanceContract");
    if (aEl) { aEl.textContent = contractAddr; aEl.setAttribute("data-contract-address", contractAddr); }
    const fromQtyNum = parseFloat(normalizeAmountForNumberInput(fromQty)) || 0;
    const defaultApprovalQty = Math.ceil(fromQtyNum) || 1;
    inputById("txtAddAllowanceQuantity").value = defaultApprovalQty.toString();
    byId("divAddAllowanceError").style.display = "none";
    byId("divAddAllowanceError").textContent = "";
    setAddAllowancePanelWaiting(false);
    resetCurrentGasConfig(swapApproveGasState);
    setGasFeeLabel("spanAddAllowanceGasFee", "");
    scheduleGasEstimation(function () {
        const amount = (inputById("txtAddAllowanceQuantity").value || "").trim();
        if (!amount || parseFloat(amount) <= 0) return null;
        return getSwapApproveTxContext(amount);
    }, "divAddAllowanceGasIcon", "spanAddAllowanceGasFee", swapApproveGasState);
}

export function showSwapMainPanel(): boolean {
    byId("divSwapConfirmPanel").style.display = "none";
    byId("divSwapRemoveAllowancePanel").style.display = "none";
    byId("divSwapAddAllowancePanel").style.display = "none";
    byId("divSwapScreenInner").style.display = "block";
    updateSwapFromAllowanceDisplay();
    setGasFeeLabel("spanSwapGasFee", "");
    scheduleSwapExecuteGasEstimation("divSwapGasIcon", "spanSwapGasFee");
    return false;
}

export function onSwapScreenBackClick(): boolean {
    if (byId("divSwapRemoveAllowancePanel").style.display !== "none" || byId("divSwapAddAllowancePanel").style.display !== "none" || byId("divSwapSuccessPanel").style.display !== "none") {
        goToFirstSwapScreen();
        return false;
    }
    if (byId("divSwapConfirmPanel").style.display !== "none") {
        showSwapMainPanel();
        return false;
    }
    showWalletScreen();
    return false;
}

export function setSwapConfirmPanelWaitingForApprovalTx(waiting: boolean): void {
    const slippageInput = inputById("txtSwapSlippage");
    const btnNext = byId<HTMLButtonElement>("btnSwapConfirmNext");
    const errDiv = byId("divSwapConfirmApprovalTxError");
    const disabled = !!waiting;
    if (slippageInput) { slippageInput.disabled = disabled; slippageInput.style.opacity = disabled ? "0.6" : ""; }
    const pwdInput = inputById("pwdSwapConfirm");
    if (pwdInput) { pwdInput.disabled = disabled; pwdInput.style.opacity = disabled ? "0.6" : ""; }
    if (btnNext) { btnNext.disabled = disabled; btnNext.style.pointerEvents = disabled ? "none" : ""; btnNext.style.opacity = disabled ? "0.6" : ""; }
    if (errDiv) { errDiv.style.display = "none"; errDiv.textContent = ""; }
}

// On swap-execute success: show the before/after success panel. On failure: re-enable
// the confirm panel so the user stays on the transaction dialog (closes the status via OK).
export function onSwapSubmitCompletedDialogClose(): void {
    const alt = byId<HTMLImageElement>("imgSendCompletedStatus");
    const status = alt ? alt.alt : "";
    if (status === "Success") {
        (async function () {
            await refreshAccountBalance();
            const fromAfter = await getSwapBalanceForSymbol(swapSuccessFromToken as string);
            const toAfter = await getSwapBalanceForSymbol(swapSuccessToToken as string);
            const gasFeeCoins = swapSuccessGasLimit != null ? formatGasFeeQ(swapSuccessGasLimit * SWAP_GAS_FEE_RATE) : "0";
            showSwapSuccessPanel(swapSuccessFromToken as string, swapSuccessToToken as string, swapSuccessFromBefore, swapSuccessToBefore, fromAfter, toAfter, gasFeeCoins);
            swapSuccessFromToken = null;
            swapSuccessToToken = null;
            swapSuccessFromBefore = null;
            swapSuccessToBefore = null;
            swapSuccessGasLimit = null;
        })();
    } else {
        setSwapConfirmPanelWaitingForApprovalTx(false);
    }
}

export async function submitSwapTransaction(quantumWallet: Wallet): Promise<void> {
    const fromValue = selectById("ddlSwapFromToken").value;
    const toValue = selectById("ddlSwapToToken").value;
    const fromQty = (inputById("txtSwapFromQuantity").value || "").trim();
    const toQty = (inputById("txtSwapToQuantity").value || "").trim();
    const slippagePercent = parseFloat(inputById("txtSwapSlippage").value) || 1;
    const gas = parseInt(resolveGasForTx(SWAP_DEFAULT_GAS).gasLimit, 10);
    try {
        const result = await submitSwapSwap({
            rpcEndpoint: (App.currentBlockchainNetwork as { rpcEndpoint: string }).rpcEndpoint,
            chainId: parseInt(String((App.currentBlockchainNetwork as { networkId: number }).networkId), 10),
            fromTokenValue: fromValue,
            toTokenValue: toValue,
            amountIn: fromQty,
            amountOut: toQty,
            lastChanged: swapLastChanged || "from",
            slippagePercent: slippagePercent,
            fromDecimals: getSwapTokenDecimals(fromValue),
            toDecimals: getSwapTokenDecimals(toValue),
            recipientAddress: App.currentWalletAddress,
            privateKey: await quantumWallet.getPrivateKey(),
            publicKey: await quantumWallet.getPublicKey(),
            gasLimit: gas,
            advancedSigningEnabled: await advancedSigningGetDefaultValue(),
        });
        if (!result || !result.success || !result.txHash) {
            setSwapConfirmPanelWaitingForApprovalTx(false);
            showWarnAlert((result && result.error) ? String(result.error) : (langJson.errors.transactionSubmissionFailed || "Transaction submission failed."));
            return;
        }
        swapSuccessGasLimit = gas;
        showSendCompletedDialog(result.txHash, onSwapSubmitCompletedDialogClose);
    } catch (err: any) {
        setSwapConfirmPanelWaitingForApprovalTx(false);
        showWarnAlert((err && err.message) ? String(err.message) : String(err));
    }
}

export async function submitRemoveAllowanceTransaction(quantumWallet: Wallet): Promise<void> {
    const fromValue = selectById("ddlSwapFromToken").value;
    const gas = parseInt(resolveGasForTx(APPROVE_DEFAULT_GAS, swapApproveGasState).gasLimit, 10);
    try {
        const result = await submitSwapRemoveAllowance({
            rpcEndpoint: (App.currentBlockchainNetwork as { rpcEndpoint: string }).rpcEndpoint,
            chainId: parseInt(String((App.currentBlockchainNetwork as { networkId: number }).networkId), 10),
            fromTokenValue: fromValue,
            privateKey: await quantumWallet.getPrivateKey(),
            publicKey: await quantumWallet.getPublicKey(),
            gasLimit: gas,
            advancedSigningEnabled: await advancedSigningGetDefaultValue(),
        });
        if (!result || !result.success || !result.txHash) {
            setRemoveAllowancePanelWaiting(false);
            showWarnAlert((result && result.error) ? String(result.error) : (langJson.errors.transactionSubmissionFailed || "Transaction submission failed."));
            return;
        }
        showSendCompletedDialog(result.txHash, function () {
            const alt = byId<HTMLImageElement>("imgSendCompletedStatus");
            if (alt && alt.alt === "Success") {
                const msg = (langJson && langJson.langValues && langJson.langValues["remove-allowance-succeeded"]) ? langJson.langValues["remove-allowance-succeeded"] : "Remove allowance succeeded.";
                showAlertAndExecuteOnClose(msg, goToFirstSwapScreen);
            } else {
                setRemoveAllowancePanelWaiting(false);
            }
        });
    } catch (err: any) {
        setRemoveAllowancePanelWaiting(false);
        showWarnAlert((err && err.message) ? String(err.message) : String(err));
    }
}

export async function submitAddAllowanceTransaction(quantumWallet: Wallet): Promise<void> {
    const fromValue = selectById("ddlSwapFromToken").value;
    const approvalAmount = (inputById("txtAddAllowanceQuantity").value || "").trim();
    const gas = parseInt(resolveGasForTx(APPROVE_DEFAULT_GAS, swapApproveGasState).gasLimit, 10);
    if (!approvalAmount || parseFloat(approvalAmount) <= 0) {
        setAddAllowancePanelWaiting(false);
        showWarnAlert(langJson.errors.approvalQuantityRequired || "Approval quantity is required.");
        return;
    }
    try {
        const result = await submitSwapAddAllowance({
            rpcEndpoint: (App.currentBlockchainNetwork as { rpcEndpoint: string }).rpcEndpoint,
            chainId: parseInt(String((App.currentBlockchainNetwork as { networkId: number }).networkId), 10),
            fromTokenValue: fromValue,
            amount: approvalAmount,
            fromDecimals: getSwapTokenDecimals(fromValue),
            privateKey: await quantumWallet.getPrivateKey(),
            publicKey: await quantumWallet.getPublicKey(),
            gasLimit: gas,
            advancedSigningEnabled: await advancedSigningGetDefaultValue(),
        });
        if (!result || !result.success || !result.txHash) {
            setAddAllowancePanelWaiting(false);
            showWarnAlert((result && result.error) ? String(result.error) : (langJson.errors.transactionSubmissionFailed || "Transaction submission failed."));
            return;
        }
        showSendCompletedDialog(result.txHash, function () {
            const alt = byId<HTMLImageElement>("imgSendCompletedStatus");
            if (alt && alt.alt === "Success") {
                const msg = (langJson && langJson.langValues && langJson.langValues["add-allowance-succeeded"]) ? langJson.langValues["add-allowance-succeeded"] : "Add allowance succeeded.";
                showAlertAndExecuteOnClose(msg, goToFirstSwapScreen);
            } else {
                setAddAllowancePanelWaiting(false);
            }
        });
    } catch (err: any) {
        setAddAllowancePanelWaiting(false);
        showWarnAlert((err && err.message) ? String(err.message) : String(err));
    }
}

let allowanceConfirmMode: string | null = null;
let swapSuccessFromToken: string | null = null;
let swapSuccessToToken: string | null = null;
let swapSuccessFromBefore: string | null = null;
let swapSuccessToBefore: string | null = null;
let swapSuccessGasLimit: number | null = null;

export function goToFirstSwapScreen(): void {
    byId("divSwapConfirmPanel").style.display = "none";
    byId("divSwapRemoveAllowancePanel").style.display = "none";
    byId("divSwapAddAllowancePanel").style.display = "none";
    byId("divSwapSuccessPanel").style.display = "none";
    byId("divSwapScreenInner").style.display = "block";
    updateSwapFromAllowanceDisplay();
    setGasFeeLabel("spanSwapGasFee", "");
    scheduleSwapExecuteGasEstimation("divSwapGasIcon", "spanSwapGasFee");
}

export function setSwapSuccessSymbolAndLink(container: HTMLElement | null, symbol: string, explorerUrl: string, shortAddr: string): void {
    if (!container) return;
    container.textContent = "";
    if (!explorerUrl || !shortAddr) {
        container.textContent = symbol || "Q";
        return;
    }
    container.appendChild(document.createTextNode(symbol + " ("));
    const a = document.createElement("a");
    a.href = "#";
    a.textContent = shortAddr;
    a.style.color = "#0066cc";
    a.style.textDecoration = "underline";
    a.onclick = function () { OpenUrl(explorerUrl); return false; };
    container.appendChild(a);
    container.appendChild(document.createTextNode(")"));
}

export function showSwapSuccessPanel(fromToken: string, toToken: string, fromBefore: string | null, toBefore: string | null, fromAfter: string | null, toAfter: string | null, gasFeeCoins: string | null): void {
    byId("divSwapScreenInner").style.display = "none";
    byId("divSwapConfirmPanel").style.display = "none";
    byId("divSwapRemoveAllowancePanel").style.display = "none";
    byId("divSwapAddAllowancePanel").style.display = "none";
    byId("divSwapSuccessPanel").style.display = "block";

    const explorerBase = App.currentBlockchainNetwork ? BLOCK_EXPLORER_ACCOUNT_TEMPLATE.replace(BLOCK_EXPLORER_DOMAIN_TEMPLATE, App.currentBlockchainNetwork.blockExplorerDomain) : "";
    const fromAddr = getSwapContractAddress(fromToken);
    const toAddr = getSwapContractAddress(toToken);
    const fromSymbol = getSwapCachedSymbol(fromToken);
    const toSymbol = getSwapCachedSymbol(toToken);
    function shortAddr(addr: string): string { return (!addr || addr === zero_address) ? "" : (String(addr).length > 10 ? String(addr).slice(0, 6) + "..." + String(addr).slice(-4) : addr); }
    const fromUrl = (fromAddr && fromAddr !== zero_address && explorerBase) ? explorerBase.replace(ADDRESS_TEMPLATE, fromAddr) : "";
    const toUrl = (toAddr && toAddr !== zero_address && explorerBase) ? explorerBase.replace(ADDRESS_TEMPLATE, toAddr) : "";

    setSwapSuccessSymbolAndLink(byId("spanSwapSuccessFromTokenDisplay"), fromSymbol, fromUrl, shortAddr(fromAddr));
    setSwapSuccessSymbolAndLink(byId("spanSwapSuccessToTokenDisplay"), toSymbol, toUrl, shortAddr(toAddr));
    setSwapSuccessSymbolAndLink(byId("tdSwapSuccessFromName"), fromSymbol, fromUrl, shortAddr(fromAddr));
    setSwapSuccessSymbolAndLink(byId("tdSwapSuccessToName"), toSymbol, toUrl, shortAddr(toAddr));

    byId("tdSwapSuccessFromBefore").textContent = fromBefore != null ? String(fromBefore) : "0";
    byId("tdSwapSuccessFromAfter").textContent = fromAfter != null ? String(fromAfter) : "0";
    byId("tdSwapSuccessToBefore").textContent = toBefore != null ? String(toBefore) : "0";
    byId("tdSwapSuccessToAfter").textContent = toAfter != null ? String(toAfter) : "0";
    byId("spanSwapSuccessGasFee").textContent = gasFeeCoins != null ? String(gasFeeCoins) : "0";
}

export function onSwapSuccessOkClick(): boolean {
    goToFirstSwapScreen();
    updateSwapBalanceLabels();
    return false;
}

export function setRemoveAllowancePanelWaiting(waiting: boolean): void {
    const btn = byId<HTMLButtonElement>("btnRemoveAllowanceRemove");
    const errDiv = byId("divRemoveAllowanceError");
    const disabled = !!waiting;
    const pwdInput = inputById("pwdRemoveAllowance");
    if (pwdInput) { pwdInput.disabled = disabled; pwdInput.style.opacity = disabled ? "0.6" : ""; }
    if (btn) { btn.disabled = disabled; btn.style.pointerEvents = disabled ? "none" : ""; btn.style.opacity = disabled ? "0.6" : ""; }
    if (errDiv) { errDiv.style.display = "none"; errDiv.textContent = ""; }
}

export function setAddAllowancePanelWaiting(waiting: boolean): void {
    const qtyInput = inputById("txtAddAllowanceQuantity");
    // The legacy selector matched the "max" link via its inline onclick attribute;
    // the codegen preserves no on* attributes, so match the link inside the row.
    const maxLink = document.querySelector<HTMLElement>("#divAddAllowanceQuantityRow a");
    const btn = byId<HTMLButtonElement>("btnAddAllowanceAdd");
    const errDiv = byId("divAddAllowanceError");
    const disabled = !!waiting;
    if (qtyInput) { qtyInput.disabled = disabled; qtyInput.style.opacity = disabled ? "0.6" : ""; }
    const pwdInput = inputById("pwdAddAllowance");
    if (pwdInput) { pwdInput.disabled = disabled; pwdInput.style.opacity = disabled ? "0.6" : ""; }
    if (maxLink) { maxLink.style.pointerEvents = disabled ? "none" : ""; maxLink.style.opacity = disabled ? "0.6" : ""; }
    if (btn) { btn.disabled = disabled; btn.style.pointerEvents = disabled ? "none" : ""; btn.style.opacity = disabled ? "0.6" : ""; }
    if (errDiv) { errDiv.style.display = "none"; errDiv.textContent = ""; }
}

export async function openRemoveAllowanceContractInExplorer(): Promise<void> {
    const addr = getSwapContractAddress(selectById("ddlSwapFromToken").value);
    const url = BLOCK_EXPLORER_ACCOUNT_TEMPLATE.replace(BLOCK_EXPLORER_DOMAIN_TEMPLATE, (App.currentBlockchainNetwork as { blockExplorerDomain: string }).blockExplorerDomain).replace(ADDRESS_TEMPLATE, addr);
    await OpenUrl(url);
}

export async function openAddAllowanceContractInExplorer(): Promise<void> {
    const addr = getSwapContractAddress(selectById("ddlSwapFromToken").value);
    const url = BLOCK_EXPLORER_ACCOUNT_TEMPLATE.replace(BLOCK_EXPLORER_DOMAIN_TEMPLATE, (App.currentBlockchainNetwork as { blockExplorerDomain: string }).blockExplorerDomain).replace(ADDRESS_TEMPLATE, addr);
    await OpenUrl(url);
}

export function showSwapApprovalTransactionReview(review: TransactionReview, mode: string): void {
    allowanceConfirmMode = mode;
    review.requirePassword = false;
    review.submitLabelKey = "submit";
    review.nonce = null;
    review.networkText = txReviewNetworkText();
    review.fromAddress = App.currentWalletAddress;
    review.onSubmit = function () {
        showLoadingAndExecuteAsync(langJson.langValues.waitWalletOpen, decryptAndUnlockWalletForSwapApproval);
    };
    showTransactionReviewDialog(review);
}

export function showSwapExecuteConfirmDialog(): void {
    const fromValue = selectById("ddlSwapFromToken").value;
    const toValue = selectById("ddlSwapToToken").value;
    const fromAmt = (inputById("txtSwapFromQuantity").value || "").trim();
    const toAmt = (inputById("txtSwapToQuantity").value || "").trim();
    function sym(v: string): string { return v === "Q" ? "Q" : (String(v).length > 10 ? String(v).slice(0, 6) + "..." + String(v).slice(-4) : v); }
    const resolved = resolveGasForTx(SWAP_DEFAULT_GAS);
    const review: TransactionReview = {
        asset: sym(fromValue) + " -> " + sym(toValue),
        contractAddress: getSwapContractAddress(fromValue),
        toAddress: App.currentWalletAddress,
        quantityLabelKey: "send-quantity",
        quantityValue: fromAmt + " " + sym(fromValue) + " for " + toAmt + " " + sym(toValue),
        gasLimit: resolved.gasLimit,
        gasFee: resolved.gasFee,
    };
    showSwapApprovalTransactionReview(review, "swapExecute");
}

export async function decryptAndUnlockWalletForSwapApproval(): Promise<void> {
    let pwdId = "pwdSwapConfirm";
    if (allowanceConfirmMode === "remove") pwdId = "pwdRemoveAllowance";
    else if (allowanceConfirmMode === "add") pwdId = "pwdAddAllowance";
    const password = (inputById(pwdId).value || "").trim();
    try {
        const quantumWallet = await walletGetByAddress(password, App.currentWalletAddress);
        if (quantumWallet == null) {
            hideWaitingBox();
            showWarnAlert(getGenericError(""));
            return;
        }
        hideWaitingBox();
        closeTransactionReviewDialog();
        if (allowanceConfirmMode === "remove") {
            allowanceConfirmMode = null;
            setRemoveAllowancePanelWaiting(true);
            await submitRemoveAllowanceTransaction(quantumWallet);
        } else if (allowanceConfirmMode === "add") {
            allowanceConfirmMode = null;
            setAddAllowancePanelWaiting(true);
            await submitAddAllowanceTransaction(quantumWallet);
        } else if (allowanceConfirmMode === "swapExecute") {
            allowanceConfirmMode = null;
            setSwapConfirmPanelWaitingForApprovalTx(true);
            await submitSwapTransaction(quantumWallet);
        }
    } catch (err: any) {
        hideWaitingBox();
        showWarnAlert((err && err.message) ? err.message : String(err));
    }
}

export function onRemoveSwapAllowanceClick(): boolean {
    if (!App.currentBlockchainNetwork) return false;
    const fromValue = selectById("ddlSwapFromToken").value;
    if (!fromValue) return false;
    byId("divSwapScreenInner").style.display = "none";
    byId("divSwapConfirmPanel").style.display = "none";
    byId("divSwapAddAllowancePanel").style.display = "none";
    byId("divSwapRemoveAllowancePanel").style.display = "block";
    const contractAddr = getSwapContractAddress(fromValue);
    const aEl = byId("aRemoveAllowanceContract");
    if (aEl) { aEl.textContent = contractAddr; aEl.setAttribute("data-contract-address", contractAddr); }
    byId("divRemoveAllowanceError").style.display = "none";
    byId("divRemoveAllowanceError").textContent = "";
    setRemoveAllowancePanelWaiting(false);
    resetCurrentGasConfig(swapApproveGasState);
    setGasFeeLabel("spanRemoveAllowanceGasFee", "");
    scheduleGasEstimation(function () { return getSwapApproveTxContext("0"); }, "divRemoveAllowanceGasIcon", "spanRemoveAllowanceGasFee", swapApproveGasState);
    return false;
}

export function onRemoveAllowanceRemoveClick(): boolean {
    const password = inputById("pwdRemoveAllowance").value;
    if (password == null || password.length < 2) {
        showWarnAlert(langJson.errors.enterQuantumPassword);
        return false;
    }
    const contractAddr = getSwapContractAddress(selectById("ddlSwapFromToken").value);
    const resolved = resolveGasForTx(APPROVE_DEFAULT_GAS, swapApproveGasState);
    const review: TransactionReview = {
        asset: langJson.langValues["remove-allowance-title"] || "Remove allowance",
        contractAddress: contractAddr,
        toAddress: contractAddr,
        quantityLabelKey: "approval-quantity",
        quantityValue: "0",
        gasLimit: resolved.gasLimit,
        gasFee: resolved.gasFee,
    };
    showSwapApprovalTransactionReview(review, "remove");
    return false;
}

export function setAddAllowanceQuantityToMax(): boolean {
    inputById("txtAddAllowanceQuantity").value = "999999999999999999";
    onAddAllowanceQuantityInput();
    return false;
}

export function onAddAllowanceQuantityInput(): void {
    if (!App.currentBlockchainNetwork) return;
    const amount = (inputById("txtAddAllowanceQuantity").value || "").trim();
    if (!amount || parseFloat(amount) <= 0) return;
    scheduleGasEstimation(function () { return getSwapApproveTxContext(amount); }, "divAddAllowanceGasIcon", "spanAddAllowanceGasFee", swapApproveGasState);
}

export function onAddAllowanceAddClick(): boolean {
    const password = inputById("pwdAddAllowance").value;
    if (password == null || password.length < 2) {
        showWarnAlert(langJson.errors.enterQuantumPassword);
        return false;
    }
    const contractAddr = getSwapContractAddress(selectById("ddlSwapFromToken").value);
    const approvalQty = (inputById("txtAddAllowanceQuantity").value || "").trim();
    const resolved = resolveGasForTx(APPROVE_DEFAULT_GAS, swapApproveGasState);
    const review: TransactionReview = {
        asset: langJson.langValues["add-allowance-title"] || "Add allowance",
        contractAddress: contractAddr,
        toAddress: contractAddr,
        quantityLabelKey: "approval-quantity",
        quantityValue: approvalQty,
        gasLimit: resolved.gasLimit,
        gasFee: resolved.gasFee,
    };
    showSwapApprovalTransactionReview(review, "add");
    return false;
}

export function onSwapConfirmNextClick(): boolean {
    const password = inputById("pwdSwapConfirm").value;
    if (password == null || password.length < 2) {
        showWarnAlert(langJson.errors.enterQuantumPassword);
        return false;
    }
    showSwapExecuteConfirmDialog();
    return false;
}
