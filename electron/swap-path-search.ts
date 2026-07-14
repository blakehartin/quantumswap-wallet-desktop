// Pure multi-hop swap route search. Port of the BFS routing fallback in the
// browser extension (quantumswap-browser-extension src/bridge/handlers/chain.js).
// Kept free of node/SDK imports so the renderer's vitest suite can unit-test it
// directly (the electron project has rootDir "electron", so the shared code
// lives here and the test imports across project boundaries).

// Maximum number of intermediate tokens between the from- and to-token.
export const SWAP_MAX_INTERMEDIATE_HOPS = 3;

export const SWAP_NO_ROUTE_ERROR =
    "No swap route exists between these two tokens: no direct pair and no route through intermediate tokens (max 3 hops).";

// Find a router path over `nodes` (= [from, ...hopCandidates, to]) using the
// given pair-existence predicate: the direct pair when it exists, otherwise the
// shortest route (BFS) through the hop candidates, limited to
// SWAP_MAX_INTERMEDIATE_HOPS intermediate tokens. Returns the address path
// ([from, ...hops, to]) or null when no route exists.
export async function searchSwapPath(
    nodes: string[],
    pairExists: (tokenA: string, tokenB: string) => Promise<boolean>,
): Promise<string[] | null> {
    const target = nodes.length - 1;
    if (await pairExists(nodes[0], nodes[target])) {
        return [nodes[0], nodes[target]];
    }

    // Query every remaining pair among the nodes in parallel (the direct
    // from->to pair was already checked above), then BFS the pair graph.
    const adj: number[][] = nodes.map(() => []);
    const checks: Promise<void>[] = [];
    for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
            if (i === 0 && j === target) continue;
            checks.push(
                pairExists(nodes[i], nodes[j]).then((exists) => {
                    if (exists) {
                        adj[i].push(j);
                        adj[j].push(i);
                    }
                }),
            );
        }
    }
    await Promise.all(checks);

    const maxEdges = SWAP_MAX_INTERMEDIATE_HOPS + 1;
    const prev: number[] = new Array(nodes.length).fill(-1);
    const depth: number[] = new Array(nodes.length).fill(-1);
    depth[0] = 0;
    const queue = [0];
    while (queue.length) {
        const cur = queue.shift() as number;
        if (cur === target) break;
        if (depth[cur] >= maxEdges) continue;
        for (const nxt of adj[cur]) {
            if (depth[nxt] !== -1) continue;
            depth[nxt] = depth[cur] + 1;
            prev[nxt] = cur;
            queue.push(nxt);
        }
    }
    if (depth[target] !== -1 && depth[target] <= maxEdges) {
        const idxPath: number[] = [];
        for (let cur = target; cur !== -1; cur = prev[cur]) idxPath.unshift(cur);
        return idxPath.map((i) => nodes[i]);
    }
    return null;
}
