import { describe, expect, it } from "vitest";
import { amountAfterSlippage, assignSequentialNonces, buildOfflineSwapPath } from "./offline-flow-core";

describe("offline transaction flow", () => {
    it("computes minimum output without floating point rounding", () => {
        expect(amountAfterSlippage("100.123456", 6, 1)).toBe("99.122221");
        expect(amountAfterSlippage("1", 18, 0.5)).toBe("0.995");
    });

    it("assigns sequential nonces in bundle order", () => {
        expect(assignSequentialNonces(["approve", "swap"], 41)).toEqual([
            { step: "approve", nonce: 41 },
            { step: "swap", nonce: 42 },
        ]);
    });

    it("builds direct and manual multi-hop paths", () => {
        expect(buildOfflineSwapPath("A", "B", [])).toEqual(["A", "B"]);
        expect(buildOfflineSwapPath("A", "D", [" B ", "C"])).toEqual(["A", "B", "C", "D"]);
        expect(() => buildOfflineSwapPath("A", "A", [])).toThrow("duplicate");
    });
});
