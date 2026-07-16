// Controller for the numbered multi-step transaction dialog (modalTxSteps).
// Ported from the quantumswap-web-app's txSteps component, adapted to the
// desktop flow: the wallet password/keys are collected once by the caller
// (transaction review dialog), then the steps run automatically in sequence.
// Each step submits a transaction, shows its hash, and polls the scan API
// (same source showSendCompletedDialog uses) until it succeeds or fails.
import { langJson } from "../lib/i18n";
import { getTransactionStatusByHash } from "../lib/api";
import { WriteTextToClipboard } from "../lib/bridge";
import { byId, networkStore, walletStore } from "./state";
import { OpenScanTxn } from "./app";

export type TxStepStatus = "pending" | "active" | "confirming" | "done" | "failed";

export interface TxStepDefinition {
    label: string;
    // Submits the step's transaction and resolves with its hash (throws on
    // submit failure; a { success: false } IPC result must be thrown by the
    // step itself so the message reaches the dialog).
    run: () => Promise<string>;
}

const TX_STEPS_POLL_INTERVAL_MS = 5000;
const TX_STEPS_MAX_POLLS = 120; // ~10 minutes per step

let txStepsRunId = 0; // invalidates the running chain when the dialog closes
let txStepsCurrentTxHash: string | null = null;
let txStepsOnClose: (() => unknown) | null = null;
let txStepsBound = false;
let txStepsProgressText = "";

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

function setTxStepsButton(labelKey: string, fallback: string, enabled: boolean): void {
    const btn = byId<HTMLButtonElement>("btnTxStepsClose");
    btn.textContent = t(labelKey, fallback);
    btn.disabled = !enabled;
}

function closeTxStepsDialog(): void {
    txStepsRunId++; // abandon any in-flight polling loop
    const dlg = byId<HTMLDialogElement>("modalTxSteps");
    dlg.style.display = "none";
    dlg.close();
    const cb = txStepsOnClose;
    txStepsOnClose = null;
    if (cb != null) void cb();
}

function bindTxStepsDialog(): void {
    if (txStepsBound) return;
    txStepsBound = true;
    byId("btnTxStepsClose").addEventListener("click", function () {
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
    // Called once every step succeeded; may return a node to display (e.g.
    // the new token's address) - built with createElement/textContent only.
    onAllDone?: () => HTMLElement | null | void;
    // Called when the dialog closes (any outcome).
    onClose?: () => unknown;
}

// Open the dialog and run the steps sequentially. Submissions are auto-run:
// the caller has already collected confirmation + password. Closing the
// dialog abandons status polling but cannot recall submitted transactions.
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

    const dlg = byId<HTMLDialogElement>("modalTxSteps");
    dlg.style.display = "block";
    dlg.showModal();

    void (async () => {
        // Wait for two animation frames so title, step rows, and Close are
        // painted before any submit / poll IPC begins (avoids layout lag).
        await new Promise<void>((resolve) => {
            requestAnimationFrame(() => {
                requestAnimationFrame(() => resolve());
            });
        });
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
                return;
            }
        }
        if (runId !== txStepsRunId) return;
        if (options.onAllDone) {
            const node = options.onAllDone();
            if (node instanceof HTMLElement) setTxStepsResult(node);
        }
        setTxStepsButton("ok", "Ok", true);
    })();
}
