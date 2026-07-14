// Runtime companion of scripts/generate-views.mjs. The generated view tree
// (src/ui/views.generated.ts) calls e()/w()/c() to rebuild the legacy DOM and
// bind the former inline on*-handlers through a typed registry.

export type LegacyHandler = (element: HTMLElement, event: Event) => unknown;

const handlerRegistry = new Map<string, LegacyHandler>();

// Registers the implementation for one legacy inline-handler code string
// (e.g. 'return copyAddress();'). The code string is used verbatim as the
// registry key so the generated views stay traceable to the old index.html.
export function registerHandlers(handlers: Record<string, LegacyHandler>): void {
    for (const code of Object.keys(handlers)) {
        if (handlerRegistry.has(code)) {
            throw new Error("Duplicate legacy handler registration: " + code);
        }
        handlerRegistry.set(code, handlers[code]);
    }
}

// Element factory. Attributes are applied in document order via setAttribute
// so the produced markup matches the legacy HTML byte-for-byte. For
// <template> elements children are appended to .content like the parser does.
export function e(
    tag: string,
    attrs: ReadonlyArray<readonly [string, string]>,
    children: ReadonlyArray<Node | string>,
    isTemplate = false,
): HTMLElement {
    const node = document.createElement(tag);
    for (const [name, value] of attrs) {
        node.setAttribute(name, value);
    }
    const target: Node = isTemplate ? (node as HTMLTemplateElement).content : node;
    for (const child of children) {
        target.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
}

// Text factory for top-level body text (whitespace between screens).
export function t(data: string): Text {
    return document.createTextNode(data);
}

// Comment factory (the legacy HTML contains marker comments).
export function c(data: string): Comment {
    return document.createComment(data);
}

// Binds a legacy inline handler: looks up the implementation registered for
// the original code string and reproduces inline-handler semantics
// (returning false prevents the default action).
export function w(node: HTMLElement, eventName: string, legacyCode: string): HTMLElement {
    node.addEventListener(eventName, (event: Event) => {
        const handler = handlerRegistry.get(legacyCode);
        if (!handler) {
            throw new Error("No handler registered for legacy inline code: " + legacyCode);
        }
        if (handler(node, event) === false) {
            event.preventDefault();
        }
    });
    return node;
}

// Test/bootstrap support: every legacy code string that appears in the
// generated views must have a registered implementation.
export function getRegisteredHandlerCodes(): string[] {
    return Array.from(handlerRegistry.keys());
}
