// Verifies the handler registry covers every legacy inline-handler code
// string that the generated views wire through w(). A missing registration
// would otherwise only surface as a runtime throw when the element is used.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { registerAppHandlers } from "./handlers";
import { getRegisteredHandlerCodes } from "../ui/render";

function extractWiredCodes(): Set<string> {
    const source = readFileSync(resolve(__dirname, "../ui/views.generated.ts"), "utf8");
    const re = /, "(?:click|change|keyup|keydown|keypress|input|focus|blur|submit|paste|mouseover|mouseout|load|scroll)", ("(?:[^"\\]|\\.)*")\)/g;
    const codes = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = re.exec(source))) {
        codes.add(JSON.parse(m[1]) as string);
    }
    return codes;
}

describe("legacy handler registry", () => {
    it("registers an implementation for every wired legacy inline-handler code", () => {
        registerAppHandlers();
        const registered = new Set(getRegisteredHandlerCodes());
        const wired = extractWiredCodes();
        expect(wired.size).toBeGreaterThan(0);

        const missing = [...wired].filter((code) => !registered.has(code));
        expect(missing).toEqual([]);
    });
});
