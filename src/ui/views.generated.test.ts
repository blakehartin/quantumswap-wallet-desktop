// Structural parity test: the programmatically generated view tree must match
// the legacy monolithic index.html node-for-node (tags, attribute order and
// values, text and comment nodes). The legacy file is committed as a fixture.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildAppBody } from "./views.generated";

const fixtureHtml = readFileSync(resolve(__dirname, "legacy-index.fixture.html"), "utf8");

interface PlainNode {
    kind: "element" | "text" | "comment";
    tag?: string;
    attrs?: [string, string][];
    data?: string;
    children?: PlainNode[];
}

// Normalizes a DOM node into a comparable plain structure. Script elements
// (and their surrounding effect) exist only in the legacy file, and on*
// attributes are replaced by addEventListener wiring in the rebuild, so both
// are excluded from comparison on the legacy side.
function normalize(node: Node): PlainNode | null {
    if (node.nodeType === Node.TEXT_NODE) {
        return { kind: "text", data: node.nodeValue ?? "" };
    }
    if (node.nodeType === Node.COMMENT_NODE) {
        return { kind: "comment", data: node.nodeValue ?? "" };
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return null;
    const element = node as HTMLElement;
    const tag = element.tagName.toLowerCase();
    if (tag === "script") return null;
    const attrs: [string, string][] = [];
    for (const attr of Array.from(element.attributes)) {
        if (/^on/i.test(attr.name)) continue;
        attrs.push([attr.name, attr.value]);
    }
    const childRoot: Node = tag === "template" ? (element as HTMLTemplateElement).content : element;
    const children: PlainNode[] = [];
    for (const child of Array.from(childRoot.childNodes)) {
        const normalized = normalize(child);
        if (normalized) children.push(normalized);
    }
    return { kind: "element", tag, attrs, children };
}

function normalizeList(nodes: Node[]): PlainNode[] {
    const result: PlainNode[] = [];
    for (const node of nodes) {
        const normalized = normalize(node);
        if (normalized) result.push(normalized);
    }
    return result;
}

describe("views.generated", () => {
    it("rebuilds the legacy index.html body 1:1", () => {
        const legacyDoc = new DOMParser().parseFromString(fixtureHtml, "text/html");
        const expected = normalizeList(Array.from(legacyDoc.body.childNodes));
        const actual = normalizeList(buildAppBody());
        expect(actual).toEqual(expected);
    });
});
