import { describe, expect, it } from "vitest";
import { createSwapWorkflowStepPlan } from "./swap-flow";

describe("createSwapWorkflowStepPlan", () => {
    it("uses only the swap step when allowance is sufficient", () => {
        expect(createSwapWorkflowStepPlan(false, "TOKENA", "TOKENB")).toEqual([
            { kind: "swap", label: "Swap TOKENA -> TOKENB" },
        ]);
    });

    it("orders exact-amount approval before swap when allowance is insufficient", () => {
        expect(createSwapWorkflowStepPlan(true, "TOKENA", "TOKENB")).toEqual([
            { kind: "approve", label: "Approve TOKENA" },
            { kind: "swap", label: "Swap TOKENA -> TOKENB" },
        ]);
    });

    it("uses token symbols and localized action text in labels", () => {
        expect(createSwapWorkflowStepPlan(true, "BOSS", "FUN", "Allow", "Exchange")).toEqual([
            { kind: "approve", label: "Allow BOSS" },
            { kind: "swap", label: "Exchange BOSS -> FUN" },
        ]);
    });
});
