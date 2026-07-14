// Dev helper: list the unique (event, legacy inline code) pairs that
// views.generated.ts wires through w(), so the handler registry in
// src/app can be checked for completeness.
import { readFileSync } from "node:fs";

const s = readFileSync("src/ui/views.generated.ts", "utf8");
const re = /, "(click|change|keyup|keydown|keypress|input|focus|blur|submit|paste|mouseover|mouseout|load|scroll)", ("(?:[^"\\]|\\.)*")\)/g;
const codes = new Set();
let m;
while ((m = re.exec(s))) {
    codes.add(m[1] + " | " + JSON.parse(m[2]));
}
console.log(codes.size + " unique handlers");
for (const c of Array.from(codes).sort()) console.log(c);
