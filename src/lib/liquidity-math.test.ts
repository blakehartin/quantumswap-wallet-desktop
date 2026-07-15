// Unit tests for the pure liquidity math (src/lib/liquidity-math.ts).
import { describe, expect, it } from "vitest";
import {
    parseBaseUnits,
    formatBaseUnits,
    quote,
    minWithSlippage,
    positionUnderlying,
    poolSharePercent,
    percentOfAmount,
    estimatedShareAfterAdd,
} from "./liquidity-math";

describe("parseBaseUnits", () => {
    it("parses whole and fractional amounts", () => {
        expect(parseBaseUnits("1", 18)).toBe(10n ** 18n);
        expect(parseBaseUnits("1.5", 18)).toBe(15n * 10n ** 17n);
        expect(parseBaseUnits("0.000001", 6)).toBe(1n);
        expect(parseBaseUnits(".5", 2)).toBe(50n);
        expect(parseBaseUnits("1,234.56", 2)).toBe(123456n);
        expect(parseBaseUnits("42", 0)).toBe(42n);
    });

    it("rejects malformed input", () => {
        expect(() => parseBaseUnits("", 18)).toThrow();
        expect(() => parseBaseUnits("abc", 18)).toThrow();
        expect(() => parseBaseUnits("-1", 18)).toThrow();
        expect(() => parseBaseUnits("1.2.3", 18)).toThrow();
        expect(() => parseBaseUnits("1e5", 18)).toThrow();
    });

    it("rejects more fraction digits than decimals", () => {
        expect(() => parseBaseUnits("1.234", 2)).toThrow("too many decimal places");
    });
});

describe("formatBaseUnits", () => {
    it("formats and trims trailing zeros", () => {
        expect(formatBaseUnits(10n ** 18n, 18)).toBe("1");
        expect(formatBaseUnits(15n * 10n ** 17n, 18)).toBe("1.5");
        expect(formatBaseUnits(0n, 18)).toBe("0");
        expect(formatBaseUnits(123456n, 2)).toBe("1234.56");
    });

    it("caps the fraction at maxFractionDigits (truncation)", () => {
        // 1.123456789 with 18 decimals, default cap 6
        expect(formatBaseUnits(1123456789n * 10n ** 9n, 18)).toBe("1.123456");
        expect(formatBaseUnits(1123456789n * 10n ** 9n, 18, 9)).toBe("1.123456789");
    });

    it("round-trips with parseBaseUnits", () => {
        const wei = parseBaseUnits("123.456789", 18);
        expect(formatBaseUnits(wei, 18, 18)).toBe("123.456789");
    });
});

describe("quote", () => {
    it("returns the proportional amount at the reserve ratio", () => {
        // reserveA=100, reserveB=200 -> 1 A quotes 2 B
        expect(quote(10n, 100n, 200n)).toBe(20n);
        expect(quote(1n, 3n, 10n)).toBe(3n); // floor
    });

    it("returns 0 for empty reserves or non-positive input", () => {
        expect(quote(0n, 100n, 200n)).toBe(0n);
        expect(quote(10n, 0n, 200n)).toBe(0n);
        expect(quote(10n, 100n, 0n)).toBe(0n);
    });
});

describe("minWithSlippage", () => {
    it("applies basis-point slippage", () => {
        expect(minWithSlippage(10000n, 0.5)).toBe(9950n);
        expect(minWithSlippage(10000n, 1)).toBe(9900n);
        expect(minWithSlippage(10000n, 0)).toBe(10000n);
    });

    it("clamps out-of-range percentages", () => {
        expect(minWithSlippage(10000n, -5)).toBe(10000n);
        expect(minWithSlippage(10000n, 200)).toBe(0n); // clamped to 100%
    });
});

describe("position estimates", () => {
    it("positionUnderlying computes the pro-rata reserve share", () => {
        // LP owns 10% of supply -> 10% of the reserve
        expect(positionUnderlying(100n, 5000n, 1000n)).toBe(500n);
        expect(positionUnderlying(0n, 5000n, 1000n)).toBe(0n);
        expect(positionUnderlying(100n, 5000n, 0n)).toBe(0n);
    });

    it("poolSharePercent returns a percentage", () => {
        expect(poolSharePercent(100n, 1000n)).toBeCloseTo(10);
        expect(poolSharePercent(1n, 3n)).toBeCloseTo(33.3333, 3);
        expect(poolSharePercent(0n, 1000n)).toBe(0);
    });

    it("percentOfAmount slices whole percents", () => {
        expect(percentOfAmount(1000n, 25)).toBe(250n);
        expect(percentOfAmount(1000n, 100)).toBe(1000n);
        expect(percentOfAmount(1000n, 0)).toBe(0n);
        expect(percentOfAmount(1000n, 150)).toBe(1000n); // clamped
    });

    it("estimatedShareAfterAdd matches the web-app estimate", () => {
        // Empty pool: first provider owns everything.
        expect(estimatedShareAfterAdd(100n, 0n, 0n)).toBe(100);
        // Adding an amount equal to the reserve doubles supply -> 50%.
        expect(estimatedShareAfterAdd(1000n, 1000n, 500n)).toBeCloseTo(50);
        expect(estimatedShareAfterAdd(0n, 1000n, 500n)).toBe(0);
    });
});
