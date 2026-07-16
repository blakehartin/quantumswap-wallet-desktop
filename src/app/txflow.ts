// Shared transaction-review -> numbered-steps handoff. The wallet password is
// collected once, keys are held only by step closures, and interactive flows
// estimate/review gas immediately before each transaction.
import { langJson } from "../lib/i18n";
import { walletGetByAddress } from "../lib/wallet";
import { ERROR_TEMPLATE, STORAGE_PATH_TEMPLATE, inputById, walletStore } from "./state";
import {
    TransactionReview,
    hideWaitingBox,
    showTransactionReviewDialog,
    showWaitingBox,
    showWarnAlert,
    txReviewNetworkText,
} from "./dialog";
import { advancedSigningGetDefaultValue } from "./settings";
import { TxStepDefinition, showTxStepsDialog } from "./txsteps";

export interface ReviewedStepsFlow {
    review: TransactionReview;
    stepsTitle: string;
    progressText?: string;
    interactive?: boolean;
    buildSteps: (privateKey: string, publicKey: string, advancedSigningEnabled: boolean) => TxStepDefinition[];
    onAllDone?: () => HTMLElement | null | void;
    onClose?: () => unknown;
}

export function showReviewThenSteps(flow: ReviewedStepsFlow): void {
    const review = flow.review;
    review.requirePassword = true;
    review.submitLabelKey = "ok";
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
                showWarnAlert(
                    langJson.errors.error
                        .replace(STORAGE_PATH_TEMPLATE, walletStore.STORAGE_PATH)
                        .replace(ERROR_TEMPLATE, ""),
                );
                return false;
            }
            const privateKey = await quantumWallet.getPrivateKey();
            const publicKey = await quantumWallet.getPublicKey();
            const advancedSigningEnabled = await advancedSigningGetDefaultValue();
            const steps = flow.buildSteps(privateKey, publicKey, advancedSigningEnabled === true);
            hideWaitingBox();
            const clearStepSecretsAndClose = function (): void {
                for (const step of steps) {
                    step.prepare = undefined;
                    step.run = async () => { throw new Error("Workflow closed."); };
                }
                if (flow.onClose) void flow.onClose();
            };
            setTimeout(function () {
                showTxStepsDialog({
                    title: flow.stepsTitle,
                    steps,
                    progressText: flow.progressText,
                    interactive: flow.interactive,
                    onAllDone: flow.onAllDone,
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

export function requireTxHash(result: any): string {
    if (!result || !result.success || !result.txHash) {
        throw new Error((result && result.error)
            ? String(result.error)
            : (langJson.errors.transactionSubmissionFailed || "Transaction submission failed."));
    }
    return String(result.txHash);
}
