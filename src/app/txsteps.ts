// Controller for the numbered multi-step transaction dialog (modalTxSteps).
// Ported from the quantumswap-web-app's txSteps component, adapted to the
// desktop flow: the wallet password/keys are collected once by the caller.
// Interactive liquidity steps estimate and wait for a user action one at a
// time; legacy single-step flows still auto-run. Submitted hashes are polled
// through the same scan API used by showSendCompletedDialog.
import { langJson } from "../lib/i18n";
import { getTransactionStatusByHash } from "../lib/api";
import { WriteTextToClipboard } from "../lib/bridge";
import { byId, networkStore, walletStore } from "./state";
import { OpenScanTxn } from "./app";
import { formatGasFeeQ } from "./gas";

export type TxStepStatus = "pending" | "active" | "ready" | "confirming" | "done" | "failed";

export interface TxStepDefinition {
    label: string;
    // Interactive workflows prepare only the current transaction, after any
    // preceding receipt has succeeded.
    prepare?: () => Promise<TxStepGasEstimate>;
    // Submits the step's transaction and resolves with its hash (throws on
    // submit failure; a { success: false } IPC result must be thrown by the
    // step itself so the message reaches the dialog).
    run: (gasLimit?: number) => Promise<string>;
}

export interface TxStepGasEstimate {
    gasLimit: string;
    gasFee: string;
    feePerGas: number;
}

const TX_STEPS_POLL_INTERVAL_MS = 5000;
const TX_STEPS_MAX_POLLS = 120; // ~10 minutes per step

let txStepsRunId = 0; // invalidates the running chain when the dialog closes
let txStepsCurrentTxHash: string | null = null;
let txStepsOnClose: (() => unknown) | null = null;
let txStepsBound = false;
let txStepsProgressText = "";
let txStepsAction: (() => void) | null = null;
let txStepsFeePerGas = 0;

function t(key: string, fallback: string): string {
    return (langJson && langJson.langValues && langJson.langValues[key]) || fallback;
}

function stepRow(num: number, label: string, state: TxStepStatus): HTMLElement {
    const li = document.createElement("li");
    li.className = "tx-step s-" + state;
    const badge = document.createElement("span");
    badge.className = "tx-badge";
    if (state === "done") {
        badge.textContent = "\u2713";
    } else if (state === "failed") {
        badge.textContent = "\u2715";
    } else if (state === "active" || state === "confirming") {
        const spinner = document.createElement("span");
        spinner.className = "tx-spinner";
        badge.appendChild(spinner);
    } else {
        badge.textContent = String(num);
    }
    const labelSpan = document.createElement("span");
    labelSpan.className = "tx-label";
    // label may embed a token symbol (untrusted); textContent keeps it inert.
    labelSpan.textContent = label;
    if (state === "confirming") {
        const confirming = document.createElement("span");
        confirming.className = "tx-substatus";
        confirming.textContent = " " + (txStepsProgressText || t("tx-step-confirming", "Confirming..."));
        labelSpan.appendChild(confirming);
    }
    li.appendChild(badge);
    li.appendChild(labelSpan);
    return li;
}

function renderSteps(steps: TxStepDefinition[], statuses: TxStepStatus[]): void {
    const list = byId("olTxStepsList");
    list.textContent = "";
    for (let i = 0; i < steps.length; i++) {
        list.appendChild(stepRow(i + 1, steps[i].label, statuses[i]));
    }
}

function setTxStepsHash(txHash: string | null): void {
    txStepsCurrentTxHash = txHash;
    const row = byId("divTxStepsHashRow");
    if (txHash == null) {
        row.style.display = "none";
        byId("pTxStepsTxHash").textContent = "";
        return;
    }
    byId("pTxStepsTxHash").textContent = txHash;
    row.style.display = "block";
}

function setTxStepsError(message: string | null): void {
    const p = byId("pTxStepsError");
    if (message == null || message === "") {
        p.style.display = "none";
        p.textContent = "";
        return;
    }
    p.textContent = message;
    p.style.display = "block";
}

// Result note shown when the whole chain finished (e.g. the deployed token's
// contract address). Built by the caller with createElement/textContent only.
function setTxStepsResult(resultNode: HTMLElement | null): void {
    const div = byId("divTxStepsResult");
    div.textContent = "";
    if (resultNode == null) {
        div.style.display = "none";
        return;
    }
    div.appendChild(resultNode);
    div.style.display = "block";
}

function setTxStepsButton(labelKey: string, fallback: string, enabled: boolean, spinning = false): void {
    const btn = byId<HTMLButtonElement>("btnTxStepsClose");
    btn.textContent = "";
    if (spinning) {
        const spinner = document.createElement("span");
        spinner.className = "tx-spinner";
        spinner.style.marginRight = "6px";
        btn.appendChild(spinner);
    }
    btn.appendChild(document.createTextNode(t(labelKey, fallback)));
    btn.disabled = !enabled;
}

function setTxStepsGasError(message: string | null): void {
    const p = byId("pTxStepsGasError");
    p.textContent = message || "";
    p.style.display = message ? "block" : "none";
}

function updateTxStepsEstimatedFee(): void {
    const input = byId<HTMLInputElement>("txtTxStepsGasLimit");
    const gasLimit = Number(input.value);
    byId("spanTxStepsGasFee").textContent =
        Number.isInteger(gasLimit) && gasLimit > 0
            ? formatGasFeeQ(gasLimit * txStepsFeePerGas)
            : "";
}

function hideTxStepsGas(): void {
    byId("divTxStepsGas").style.display = "none";
    byId<HTMLInputElement>("txtTxStepsGasLimit").value = "";
    byId("spanTxStepsGasFee").textContent = "";
    setTxStepsGasError(null);
    txStepsFeePerGas = 0;
}

function closeTxStepsDialog(): void {
    txStepsRunId++; // abandon any in-flight polling loop
    const dlg = byId<HTMLDialogElement>("modalTxSteps");
    dlg.style.display = "none";
    dlg.close();
    txStepsAction = null;
    hideTxStepsGas();
    const cb = txStepsOnClose;
    txStepsOnClose = null;
    if (cb != null) void cb();
}

function bindTxStepsDialog(): void {
    if (txStepsBound) return;
    txStepsBound = true;
    byId("btnTxStepsClose").addEventListener("click", function () {
        if (txStepsAction) txStepsAction();
    });
    byId("btnTxStepsDismiss").addEventListener("click", function () {
        closeTxStepsDialog();
    });
    byId("txtTxStepsGasLimit").addEventListener("input", function () {
        setTxStepsGasError(null);
        updateTxStepsEstimatedFee();
    });
    byId<HTMLDialogElement>("modalTxSteps").addEventListener("cancel", function (event) {
        event.preventDefault();
        closeTxStepsDialog();
    });
    byId("divTxStepsCopy").addEventListener("click", function (event) {
        const el = event.currentTarget as HTMLElement;
        if (txStepsCurrentTxHash) void WriteTextToClipboard(txStepsCurrentTxHash).then(() => el.blur());
    });
    byId("divTxStepsExplorer").addEventListener("click", function (event) {
        const el = event.currentTarget as HTMLElement;
        if (txStepsCurrentTxHash) void OpenScanTxn(txStepsCurrentTxHash).then(() => el.blur());
    });
}

// Poll the scan API until the tx reaches a terminal state. Throws on failure
// or timeout; returns normally on success. Abandoned silently (throws a
// cancellation) when the dialog was closed (runId changed).
async function waitForTxSuccess(txHash: string, runId: number): Promise<void> {
    for (let i = 0; i < TX_STEPS_MAX_POLLS; i++) {
        await new Promise((resolve) => setTimeout(resolve, TX_STEPS_POLL_INTERVAL_MS));
        if (runId !== txStepsRunId) throw new Error("__txsteps_cancelled__");
        if (!networkStore.currentBlockchainNetwork) continue;
        // getTransactionStatusByHash never throws; scan-API errors come back as
        // { status: "unknown" } and simply keep the polling loop going.
        const res = await getTransactionStatusByHash(
            (networkStore.currentBlockchainNetwork as { scanApiDomain: string }).scanApiDomain,
            walletStore.currentWalletAddress,
            txHash
        );
        if (runId !== txStepsRunId) throw new Error("__txsteps_cancelled__");
        if (res.status === "succeeded") return;
        if (res.status === "failed") {
            throw new Error(res.error ? String(res.error) : t("tx-step-failed-onchain", "The transaction failed on-chain."));
        }
    }
    throw new Error(t("tx-step-timeout", "Timed out waiting for the transaction to confirm. Check the block explorer before retrying."));
}

export interface TxStepsOptions {
    title: string;
    steps: TxStepDefinition[];
    progressText?: string;
    interactive?: boolean;
    // Called once every step succeeded; may return a node to display (e.g.
    // the new token's address) - built with createElement/textContent only.
    onAllDone?: () => HTMLElement | null | void;
    // Called when the dialog closes (any outcome).
    onClose?: () => unknown;
}

function afterTwoPaints(): Promise<void> {
    return new Promise<void>((resolve) => {
        requestAnimationFrame(() => {
            requestAnimationFrame(() => resolve());
        });
    });
}

// Open the numbered status dialog. Single-step legacy flows auto-run; compound
// liquidity flows prepare and submit only when the user clicks each action.
export function showTxStepsDialog(options: TxStepsOptions): void {
    bindTxStepsDialog();
    txStepsRunId++;
    const runId = txStepsRunId;
    const steps = options.steps;
    // Render the first spinner before opening the dialog. RPC submission is
    // deferred until after this initial UI has painted.
    const statuses: TxStepStatus[] = steps.map((_, index) => index === 0 ? "active" : "pending");
    txStepsOnClose = options.onClose || null;
    txStepsProgressText = options.progressText || t("tx-step-confirming", "Confirming...");

    byId("h3TxStepsTitle").textContent = options.title;
    renderSteps(steps, statuses);
    setTxStepsHash(null);
    setTxStepsError(null);
    setTxStepsResult(null);
    setTxStepsButton("close", "Close", true);
    txStepsAction = closeTxStepsDialog;
    hideTxStepsGas();

    const dlg = byId<HTMLDialogElement>("modalTxSteps");
    dlg.style.display = "block";
    dlg.showModal();

    if (options.interactive) {
        let currentIndex = 0;
        let running = false;

        const failCurrent = (err: unknown): void => {
            if (runId !== txStepsRunId) return;
            const msg = String((err as { message?: unknown })?.message ?? err ?? "");
            if (msg === "__txsteps_cancelled__") return;
            statuses[currentIndex] = "failed";
            renderSteps(steps, statuses);
            setTxStepsError(t("tx-step-failed", "Step failed.") + " " + msg);
            setTxStepsButton("close", "Close", true);
            txStepsAction = closeTxStepsDialog;
        };

        const finishAll = (): void => {
            hideTxStepsGas();
            if (options.onAllDone) {
                const node = options.onAllDone();
                if (node instanceof HTMLElement) setTxStepsResult(node);
            }
            setTxStepsButton("ok", "Ok", true);
            txStepsAction = closeTxStepsDialog;
        };

        const prepareCurrent = async (): Promise<void> => {
            if (runId !== txStepsRunId) return;
            if (currentIndex >= steps.length) {
                finishAll();
                return;
            }
            const step = steps[currentIndex];
            statuses[currentIndex] = "active";
            renderSteps(steps, statuses);
            setTxStepsHash(null);
            setTxStepsError(null);
            setTxStepsGasError(null);
            byId("divTxStepsGas").style.display = "block";
            byId("lblTxStepsGasAction").textContent = step.label;
            const gasInput = byId<HTMLInputElement>("txtTxStepsGasLimit");
            gasInput.value = "";
            gasInput.disabled = true;
            byId("spanTxStepsGasFee").textContent = "";
            setTxStepsButton("tx-step-estimating-gas", "Estimating gas...", false, true);
            txStepsAction = null;
            try {
                await afterTwoPaints();
                if (!step.prepare) throw new Error("Gas preparation is unavailable for this step.");
                const estimate = await step.prepare();
                if (runId !== txStepsRunId) return;
                txStepsFeePerGas = estimate.feePerGas;
                gasInput.value = estimate.gasLimit;
                gasInput.disabled = false;
                updateTxStepsEstimatedFee();
                statuses[currentIndex] = "ready";
                renderSteps(steps, statuses);
                setTxStepsButton("", step.label, true);
                txStepsAction = () => { void runCurrent(); };
                setTimeout(() => gasInput.focus(), 0);
            } catch (err) {
                failCurrent(err);
            }
        };

        const runCurrent = async (): Promise<void> => {
            if (running || currentIndex >= steps.length || runId !== txStepsRunId) return;
            const gasInput = byId<HTMLInputElement>("txtTxStepsGasLimit");
            const gasLimit = Number(gasInput.value);
            if (!Number.isInteger(gasLimit) || gasLimit <= 0) {
                setTxStepsGasError(t("tx-step-invalid-gas", "Enter a valid positive gas limit."));
                gasInput.focus();
                return;
            }
            running = true;
            statuses[currentIndex] = "active";
            renderSteps(steps, statuses);
            gasInput.disabled = true;
            setTxStepsGasError(null);
            setTxStepsButton("tx-step-submitting", "Submitting...", false, true);
            txStepsAction = null;
            try {
                const txHash = await steps[currentIndex].run(gasLimit);
                if (runId !== txStepsRunId) return;
                statuses[currentIndex] = "confirming";
                renderSteps(steps, statuses);
                setTxStepsHash(txHash);
                setTxStepsButton("tx-step-confirming", "Confirming...", false, true);
                await waitForTxSuccess(txHash, runId);
                if (runId !== txStepsRunId) return;
                statuses[currentIndex] = "done";
                renderSteps(steps, statuses);
                currentIndex++;
                running = false;
                await prepareCurrent();
            } catch (err) {
                running = false;
                failCurrent(err);
            }
        };

        void prepareCurrent();
        return;
    }

    void (async () => {
        // Wait for two animation frames so title, step rows, and Close are
        // painted before any submit / poll IPC begins (avoids layout lag).
        await afterTwoPaints();
        if (runId !== txStepsRunId) return;

        for (let i = 0; i < steps.length; i++) {
            if (runId !== txStepsRunId) return;
            statuses[i] = "active";
            renderSteps(steps, statuses);
            // Later steps also get a painted spinner before their RPC starts.
            await new Promise<void>((resolve) => {
                requestAnimationFrame(() => resolve());
            });
            if (runId !== txStepsRunId) return;
            try {
                const txHash = await steps[i].run();
                if (runId !== txStepsRunId) return;
                statuses[i] = "confirming";
                renderSteps(steps, statuses);
                setTxStepsHash(txHash);
                await waitForTxSuccess(txHash, runId);
                if (runId !== txStepsRunId) return;
                statuses[i] = "done";
                renderSteps(steps, statuses);
            } catch (err) {
                if (runId !== txStepsRunId) return;
                const msg = String((err as { message?: unknown })?.message ?? err ?? "");
                if (msg === "__txsteps_cancelled__") return;
                statuses[i] = "failed";
                renderSteps(steps, statuses);
                setTxStepsError(t("tx-step-failed", "Step failed.") + " " + msg);
                setTxStepsButton("close", "Close", true);
                txStepsAction = closeTxStepsDialog;
                return;
            }
        }
        if (runId !== txStepsRunId) return;
        if (options.onAllDone) {
            const node = options.onAllDone();
            if (node instanceof HTMLElement) setTxStepsResult(node);
        }
        setTxStepsButton("ok", "Ok", true);
        txStepsAction = closeTxStepsDialog;
    })();
}
