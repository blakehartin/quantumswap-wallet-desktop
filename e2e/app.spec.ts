// Electron smoke test: launches the built app (npm run build must have run)
// with a clean user-data directory and verifies the first-run experience.
import { test, expect, _electron as electron, ElectronApplication, Page } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let app: ElectronApplication;
let page: Page;

test.beforeAll(async () => {
    const userDataDir = mkdtempSync(join(tmpdir(), "qswallet-e2e-"));
    app = await electron.launch({
        args: ["."],
        env: { ...process.env, E2E_USER_DATA_DIR: userDataDir },
    });
    page = await app.firstWindow();
});

test.afterAll(async () => {
    await app.close();
});

test("first run shows the EULA dialog", async () => {
    // initApp() loads en-us.json, then shows the EULA for a fresh profile.
    const eulaDialog = page.locator("#modalEulaDialog");
    await expect(eulaDialog).toHaveAttribute("open", "", { timeout: 15000 });
    await expect(page.locator("#divIAgree")).toBeVisible();
    // Localized EULA text replaced the placeholder markup (showEula sets it
    // from en-us.json as a single text node).
    await expect(page.locator("#divEula")).not.toContainText("hello world");
    await expect(page.locator("#divEula")).not.toHaveText("");
});

test("window title comes from en-us.json plus the app version", async () => {
    await expect(page).toHaveTitle(/Quantum.* \d+\.\d+\.\d+/);
});

test("accepting the EULA advances to onboarding", async () => {
    await page.locator("#divIAgree").click();
    await expect(page.locator("#modalEulaDialog")).not.toHaveAttribute("open", "");
    // Fresh profile has no main key, so the app proceeds toward onboarding
    // (network selection dialog or welcome/info screen).
    await expect(page.locator("#modalNetworkDialog[open], #welcomeScreen, #infoScreen")).not.toHaveCount(0);
});
