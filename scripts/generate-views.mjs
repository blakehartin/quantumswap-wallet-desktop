// One-time code generator: parses the legacy monolithic index.html and emits
// src/ui/views.generated.ts, which rebuilds the exact same DOM tree
// programmatically (same elements, attribute order, text/whitespace nodes and
// comments). Inline on* handlers are converted to wire() calls that bind
// listeners from the typed handler registry (src/app/handlers.ts).
//
// The emitted file is committed as source; re-run this script only if the
// legacy HTML ever needs to be re-imported:
//   node scripts/generate-views.mjs [path-to-old-index.html]
//
// generateViewsSource() is also imported by a unit test that regenerates the
// file from src/ui/legacy-index.fixture.html and fails if the committed
// views.generated.ts has drifted from the generator output.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const q = (s) => JSON.stringify(s);

export function generateViewsSource(html) {
  const dom = new JSDOM(html);
  const { document, Node } = dom.window;
  let wireCount = 0;

  function emitNode(node, indent) {
    const pad = "    ".repeat(indent);
    if (node.nodeType === Node.TEXT_NODE) {
      return pad + q(node.nodeValue);
    }
    if (node.nodeType === Node.COMMENT_NODE) {
      return pad + `c(${q(node.nodeValue)})`;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) {
      throw new Error(`Unsupported node type ${node.nodeType}`);
    }

    const tag = node.tagName.toLowerCase();
    const attrs = [];
    const wires = [];
    for (const attr of node.attributes) {
      if (/^on/i.test(attr.name)) {
        wires.push([attr.name.slice(2).toLowerCase(), attr.value]);
      } else {
        attrs.push([attr.name, attr.value]);
      }
    }
    wireCount += wires.length;

    const attrsSrc =
      attrs.length === 0
        ? "[]"
        : "[" + attrs.map(([n, v]) => `[${q(n)}, ${q(v)}]`).join(", ") + "]";

    // <template> children live under .content and scripts are dropped (the new
    // app is bundled; legacy <script src> tags do not apply).
    if (tag === "script") return null;

    const childSources = [];
    const childList = tag === "template" ? node.content.childNodes : node.childNodes;
    for (const child of childList) {
      const src = emitNode(child, indent + 1);
      if (src !== null) childSources.push(src);
    }

    const kids =
      childSources.length === 0 ? "[]" : "[\n" + childSources.join(",\n") + `,\n${pad}]`;

    let expr = `e(${q(tag)}, ${attrsSrc}, ${kids}${tag === "template" ? ", true" : ""})`;
    for (const [event, code] of wires) {
      expr = `w(${expr}, ${q(event)}, ${q(code)})`;
    }
    return pad + expr;
  }

  const bodyParts = [];
  for (const child of document.body.childNodes) {
    let src = emitNode(child, 2);
    if (src === null) continue;
    // Top-level text must be real Text nodes (children of e() are converted
    // automatically, but the body list is returned as Node[]).
    if (child.nodeType === Node.TEXT_NODE) {
      src = "    ".repeat(2) + `t(${q(child.nodeValue)})`;
    }
    bodyParts.push(src);
  }

  const source = `// GENERATED FILE - do not edit by hand.
// Produced by scripts/generate-views.mjs from the legacy index.html.
// Rebuilds the legacy <body> DOM 1:1 (same elements, attribute order,
// whitespace text nodes and comments) so styles.css renders identically.
// Inline on*-handlers from the legacy HTML are bound through the typed
// handler registry (see src/app/handlers.ts) via w().

import { e, w, c, t } from "./render";

export function buildAppBody(): Node[] {
    return [
${bodyParts.join(",\n")},
    ];
}
`;

  return { source, topLevelNodeCount: bodyParts.length, wireCount };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  const sourcePath = resolve(process.argv[2] ?? "src/ui/legacy-index.fixture.html");
  const outPath = resolve("src/ui/views.generated.ts");

  const html = readFileSync(sourcePath, "utf8");
  const { source, topLevelNodeCount, wireCount } = generateViewsSource(html);

  writeFileSync(outPath, source);
  console.log(
    `generate-views: wrote ${outPath} (${topLevelNodeCount} top-level nodes, ${wireCount} wired handlers)`,
  );
}
