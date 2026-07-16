export type SwapWorkflowStepKind = "approve" | "swap";

export interface SwapWorkflowStepPlan {
    kind: SwapWorkflowStepKind;
    label: string;
}

// Pure workflow planning kept separate from DOM/RPC code so the conditional
// step order and user-facing symbols can be verified directly.
export function createSwapWorkflowStepPlan(
    needsApproval: boolean,
    fromSymbol: string,
    toSymbol: string,
    approveText = "Approve",
    swapText = "Swap",
): SwapWorkflowStepPlan[] {
    const steps: SwapWorkflowStepPlan[] = [];
    if (needsApproval) {
        steps.push({ kind: "approve", label: approveText + " " + fromSymbol });
    }
    steps.push({ kind: "swap", label: swapText + " " + fromSymbol + " -> " + toSymbol });
    return steps;
}
