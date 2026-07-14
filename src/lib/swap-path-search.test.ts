import { describe, expect, it, vi } from "vitest";
import { searchSwapPath, SWAP_MAX_INTERMEDIATE_HOPS } from "../../electron/swap-path-search";

// Node lists mirror findSwapPath's layout: [from, ...hopCandidates, to].
const FROM = "0xFROM";
const TO = "0xTO";
const WQ = "0xWQ";
const H1 = "0xH1";
const H2 = "0xH2";
const H3 = "0xH3";

// Build a pair predicate from an undirected edge list.
function pairsOf(edges: [string, string][]): (a: string, b: string) => Promise<boolean> {
    return (a, b) => Promise.resolve(edges.some(([x, y]) => (x === a && y === b) || (x === b && y === a)));
}

describe("searchSwapPath", () => {
    it("returns the direct pair without querying other edges", async () => {
        const pairExists = vi.fn(pairsOf([[FROM, TO]]));
        const path = await searchSwapPath([FROM, WQ, TO], pairExists);
        expect(path).toEqual([FROM, TO]);
        expect(pairExists).toHaveBeenCalledTimes(1);
        expect(pairExists).toHaveBeenCalledWith(FROM, TO);
    });

    it("falls back to a 1-hop route through an intermediate when no direct pair exists", async () => {
        const path = await searchSwapPath([FROM, WQ, TO], pairsOf([[FROM, WQ], [WQ, TO]]));
        expect(path).toEqual([FROM, WQ, TO]);
    });

    it("prefers the shortest route when multiple exist", async () => {
        const path = await searchSwapPath(
            [FROM, WQ, H1, H2, TO],
            pairsOf([
                [FROM, WQ], [WQ, H1], [H1, H2], [H2, TO], // 3-hop route
                [FROM, H1], [H1, TO], // 1-hop route
            ]),
        );
        expect(path).toEqual([FROM, H1, TO]);
    });

    it("finds a route using the maximum allowed number of intermediates", async () => {
        const path = await searchSwapPath(
            [FROM, WQ, H1, H2, TO],
            pairsOf([[FROM, WQ], [WQ, H1], [H1, H2], [H2, TO]]),
        );
        expect(path).toEqual([FROM, WQ, H1, H2, TO]);
        expect(path!.length - 2).toBe(SWAP_MAX_INTERMEDIATE_HOPS);
    });

    it("returns null when the only route needs more than the maximum intermediates", async () => {
        const path = await searchSwapPath(
            [FROM, WQ, H1, H2, H3, TO],
            pairsOf([[FROM, WQ], [WQ, H1], [H1, H2], [H2, H3], [H3, TO]]),
        );
        expect(path).toBeNull();
    });

    it("returns null when no route exists", async () => {
        const path = await searchSwapPath([FROM, WQ, TO], pairsOf([[FROM, WQ]]));
        expect(path).toBeNull();
    });
});
