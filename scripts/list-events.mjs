// Dev helper: list every event name wired through w() in views.generated.ts.
import { readFileSync } from "node:fs";

const s = readFileSync("src/ui/views.generated.ts", "utf8");
const re = /\), "([a-z]+)", "/g;
const names = new Map();
let m;
while ((m = re.exec(s))) {
    names.set(m[1], (names.get(m[1]) || 0) + 1);
}
console.log([...names.entries()]);
