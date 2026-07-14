// Renderer entry point. Replaces the legacy inline bootstrap script at the
// bottom of the old index.html: builds the body DOM (formerly static HTML),
// registers the legacy inline-handler implementations, performs the
// script-eval-time element bindings of dialog.js/send.js, and then runs the
// same startup sequence the old inline <script> did.
import { buildAppBody } from "./ui/views.generated";
import { registerAppHandlers } from "./app/handlers";
import { initDialogs, showErrorAndLockup } from "./app/dialog";
import { initSend } from "./app/send";
import { initApp, showRestoreWalletLabel } from "./app/app";
import { applyConfiguredTheme } from "./app/theme";

async function bootstrap(): Promise<void> {
    registerAppHandlers();

    // Theme is decided by package.json "name" (quantum for the first-party
    // package, legacy grey otherwise); applied while the body is still empty
    // so there is no unthemed flash.
    await applyConfiguredTheme();

    for (const node of buildAppBody()) {
        document.body.appendChild(node);
    }

    // The legacy scripts ran after the static body existed and did their
    // element lookups/bindings at eval time; same order here.
    initDialogs();
    initSend();

    // window.onload in the legacy page; the DOM is fully built at this point.
    document.getElementById("filRestoreWallet")!.addEventListener("change", showRestoreWalletLabel);

    document.querySelectorAll<HTMLElement>('[role="button"]').forEach(function (el) {
        el.addEventListener("keypress", function (e: KeyboardEvent) {
            if (e.key === "Enter") {
                el.click();
            }
        });
    });

    // Close the burger dropdown when clicking anywhere outside of it.
    document.addEventListener("click", function (event) {
        const menu = document.getElementById("burgerMenu");
        const dropdown = document.getElementById("burgerDropdown");
        if (!menu || !dropdown || dropdown.style.display !== "block") return;
        if (!menu.contains(event.target as Node)) {
            dropdown.style.display = "none";
        }
    });

    initApp();
}

window.onerror = (message) => {
    showErrorAndLockup(message);
};

window.addEventListener("unhandledrejection", (event) => {
    const reason = (event as PromiseRejectionEvent).reason;
    const detail = (reason && reason.message) ? String(reason.message) : String(reason);
    showErrorAndLockup(detail);
});

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { void bootstrap(); });
} else {
    void bootstrap();
}
