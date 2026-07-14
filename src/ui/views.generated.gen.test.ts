// Guards the committed views.generated.ts against drift: regenerates it from
// the legacy fixture with the same generator and requires an exact match.
// If this fails, either re-run `node scripts/generate-views.mjs` (fixture or
// generator changed) or revert manual edits to views.generated.ts.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain .mjs module without type declarations
import { generateViewsSource } from "../../scripts/generate-views.mjs";

describe("views.generated.ts regeneration parity", () => {
    it("matches the generator output for the committed legacy fixture", () => {
        const fixture = readFileSync(resolve(__dirname, "legacy-index.fixture.html"), "utf8");
        const committed = readFileSync(resolve(__dirname, "views.generated.ts"), "utf8");

        const { source } = generateViewsSource(fixture);
        // Normalize line endings: git may check the file out with CRLF on Windows.
        expect(committed.replace(/\r\n/g, "\n")).toBe(source.replace(/\r\n/g, "\n"));
    });
});
