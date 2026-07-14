// Tiny typed DOM builder used to construct the UI programmatically.
// The generated tree mirrors the old monolithic index.html 1:1 (same ids,
// classes, inline styles and attribute values) so styles.css applies unchanged.

export type ElChild = Node | string | null | undefined;

export type ElAttrs = Record<string, string | number | boolean | EventListener>;

const PROPERTY_KEYS = new Set(["value", "checked", "disabled", "readOnly", "selected", "indeterminate"]);

export function el<K extends keyof HTMLElementTagNameMap>(
    tag: K,
    attrs: ElAttrs = {},
    children: ElChild[] = [],
): HTMLElementTagNameMap[K] {
    const node = document.createElement(tag);
    for (const key of Object.keys(attrs)) {
        const value = attrs[key];
        if (typeof value === "function") {
            // "onclick" -> "click"
            node.addEventListener(key.replace(/^on/, ""), value);
        } else if (PROPERTY_KEYS.has(key)) {
            (node as unknown as Record<string, unknown>)[key] = value;
        } else if (typeof value === "boolean") {
            if (value) node.setAttribute(key, "");
        } else {
            node.setAttribute(key, String(value));
        }
    }
    appendChildren(node, children);
    return node;
}

export function appendChildren(node: Node, children: ElChild[]): void {
    for (const child of children) {
        if (child == null) continue;
        if (typeof child === "string") {
            node.appendChild(document.createTextNode(child));
        } else {
            node.appendChild(child);
        }
    }
}

export function text(value: string): Text {
    return document.createTextNode(value);
}

export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
    return document.getElementById(id) as T;
}
