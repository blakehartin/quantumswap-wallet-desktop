// Swap screen (main, confirm, remove-allowance, add-allowance and success
// panels), extracted 1:1 from the legacy fixture.
import { el } from "../ui/dom";
import type { ScreenModule } from "../ui/screens";
import { togglePasswordBox } from "../app/app";
import {
    copySwapFromContractAddress,
    copySwapToContractAddress,
    debouncedUpdateFromQuantityFromTo,
    debouncedUpdateToQuantityFromFrom,
    onAddAllowanceAddClick,
    onAddAllowanceGasIconClick,
    onAddAllowanceQuantityInput,
    onRemoveAllowanceGasIconClick,
    onRemoveAllowanceRemoveClick,
    onRemoveSwapAllowanceClick,
    onSwapConfirmGasIconClick,
    onSwapConfirmNextClick,
    onSwapGasIconClick,
    onSwapNextClick,
    onSwapScreenBackClick,
    onSwapSuccessOkClick,
    onToggleSwapUnrecognized,
    openAddAllowanceContractInExplorer,
    openRemoveAllowanceContractInExplorer,
    openSwapFromContractInExplorer,
    openSwapToContractInExplorer,
    setAddAllowanceQuantityToMax,
    setSwapFromQuantityToBalance,
    setSwapToQuantityToBalance,
    updateSwapScreenInfo,
} from "../app/swap";

const SWAP_PANEL_STYLE = "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto; max-height:590px; display: none;";
const SWAP_PWD_STYLE = "text-align: left; width: 200px; border: 1px solid #ccc; border-radius: 6px; padding: 6px;";

function passwordEye(passwordBoxId: string, tabindex: string): HTMLElement {
    return el("img", {
        src: "assets/svg/eye-outline.svg", alt: "Show Password", class: "qs-eye",
        "data-alt-key": "show-password", role: "button", tabindex,
        onclick: (event: Event) => togglePasswordBox(event.currentTarget as HTMLElement, passwordBoxId),
    });
}

function buildSwapMainPanel(): HTMLElement {
    return el("div", { id: "divSwapScreenInner", class: "roundex-box scrollbar", style: "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto; max-height:690px;" }, [
        el("div", { class: "gas-header-row" }, [
            el("div", { class: "heading bold", "data-lang-key": "swap" }, ["Swap"]),
            el("div", { class: "gas-header-right" }, [
                el("span", { id: "spanSwapGasFee", class: "gas-fee-label" }),
                el("div", { id: "divSwapGasIcon", class: "gas-container", role: "button", tabindex: "343", onclick: () => onSwapGasIconClick() }),
            ]),
        ]),
        el("div", { class: "divider" }),
        el("div", { id: "divSwapShowUnrecognized", style: "display:none; text-align:left; margin-bottom:8px;" }, [
            el("input", { type: "checkbox", id: "chkSwapShowUnrecognized", tabindex: "320", onchange: () => onToggleSwapUnrecognized() }),
            el("label", {
                for: "chkSwapShowUnrecognized", tabindex: "0", "data-lang-key": "show-unrecognized-tokens", style: "cursor:pointer; color:black;",
                onkeydown: (event: Event) => {
                    const key = (event as KeyboardEvent).key;
                    if (key === "Enter" || key === " ") {
                        event.preventDefault();
                        (document.getElementById("chkSwapShowUnrecognized") as HTMLInputElement).click();
                    }
                },
            }, ["Show unrecognized tokens"]),
        ]),
        el("div", { class: "input_container", style: "gap:2px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "swap-from-token", style: "margin-top: 3px;" }, ["From token"]),
            el("div", { class: "selectwrapper", style: "width:100%; height:40px; box-sizing:border-box;" }, [
                el("select", { id: "ddlSwapFromToken", class: "selectbox", style: "height:100%; box-sizing:border-box; padding:7px 10px;", tabindex: "321", onchange: () => { void updateSwapScreenInfo(); } }),
            ]),
            el("div", { class: "input_container", style: "margin-top:3px;gap:2px;" }, [
                el("div", { style: "font-size: 0.85em; color: #372339;" }, [
                    el("span", { "data-lang-key": "balance" }, ["Balance"]),
                    ": ",
                    el("span", { id: "spanSwapFromBalance", role: "button", tabindex: "322", class: "swap-balance-label", style: "cursor:pointer;text-decoration:underline;", onclick: () => setSwapFromQuantityToBalance() }, ["0"]),
                ]),
                el("div", { id: "divSwapFromAllowanceRow", style: "display: none; font-size: 0.85em; color: #372339; margin-top:4px;" }, [
                    el("span", { "data-lang-key": "allowance" }, ["Allowance"]),
                    ": ",
                    el("span", { id: "spanSwapFromAllowance" }, ["0"]),
                    " ",
                    el("a", { href: "#", id: "aSwapRemoveAllowance", "data-lang-key": "remove-allowance", style: "margin-left:8px;color:#0066cc;cursor:pointer;text-decoration:underline;", onclick: (event: Event) => { event.preventDefault(); onRemoveSwapAllowanceClick(); } }, ["Remove allowance"]),
                ]),
                el("div", { id: "divSwapFromContractRow", style: "font-size: 0.85em; color: #372339; margin-top:4px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 6px;" }, [
                    el("a", { href: "#", id: "aSwapFromContract", tabindex: "323", style: "color: inherit; text-decoration: underline; word-break: break-all;", onclick: (event: Event) => { event.preventDefault(); void openSwapFromContractInExplorer(); } }, ["..."]),
                    el("span", { class: "copy-container copy-container-small", role: "button", style: "flex-shrink: 0; width:15px; height:15px; cursor:pointer;", tabindex: "324", id: "divCopySwapFromContract", title: "Copy", onclick: () => { void copySwapFromContractAddress(); } }),
                ]),
            ]),
            el("input", {
                class: "tab-name qs-input-strong",
                type: "number", autocomplete: "off", id: "txtSwapFromQuantity", name: "swap_from_quantity", "data-placeholder-key": "quantity",
                placeholder: "Quantity", tabindex: "325", min: "0", step: "any", oninput: () => debouncedUpdateToQuantityFromFrom(),
            }),
            el("div", { class: "divider" }),
        ]),
        el("div", { class: "input_container", style: "gap:2px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "swap-to-token", style: "margin-top: 3px;" }, ["To token"]),
            el("div", { class: "selectwrapper", style: "width:100%; height:40px; box-sizing:border-box;" }, [
                el("select", { id: "ddlSwapToToken", class: "selectbox", style: "height:100%; box-sizing:border-box; padding:7px 10px;", tabindex: "326", onchange: () => { void updateSwapScreenInfo(); } }),
            ]),
            el("div", { class: "input_container", style: "margin-top:3px;gap:2px;" }, [
                el("div", { style: "font-size: 0.85em; color: #372339;" }, [
                    el("span", { "data-lang-key": "balance" }, ["Balance"]),
                    ": ",
                    el("span", { id: "spanSwapToBalance", role: "button", tabindex: "327", class: "swap-balance-label", style: "cursor:pointer;text-decoration:underline;", onclick: () => setSwapToQuantityToBalance() }, ["0"]),
                ]),
                el("div", { id: "divSwapToContractRow", style: "font-size: 0.85em; color: #372339; margin-top:4px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 6px;" }, [
                    el("a", { href: "#", id: "aSwapToContract", tabindex: "328", style: "color: inherit; text-decoration: underline; word-break: break-all;", onclick: (event: Event) => { event.preventDefault(); void openSwapToContractInExplorer(); } }, ["..."]),
                    el("span", { class: "copy-container copy-container-small", role: "button", style: "flex-shrink: 0; width:15px; height:15px; cursor:pointer;", tabindex: "329", id: "divCopySwapToContract", title: "Copy", onclick: () => { void copySwapToContractAddress(); } }),
                ]),
            ]),
            el("input", {
                class: "tab-name qs-input-strong",
                type: "number", autocomplete: "off", id: "txtSwapToQuantity", name: "swap_to_quantity", "data-placeholder-key": "quantity",
                placeholder: "Quantity", tabindex: "330", min: "0", step: "any", oninput: () => debouncedUpdateFromQuantityFromTo(),
            }),
            el("div", { class: "divider" }),
        ]),
        el("div", { id: "divSwapRoutePath", style: "display: none; font-size: 0.85em; color: #ffffff; margin-top:6px; word-break: break-all;" }, [
            el("span", { "data-lang-key": "swap-route" }, ["Route"]),
            ": ",
            el("span", { id: "spanSwapRoutePath" }),
        ]),
        el("div", { style: "display: flex; align-items: center; justify-content: flex-end; gap: 10px;margin-top:10px;" }, [
            el("div", { id: "divSwapQuoteLoading", style: "display: none;" }, [
                el("img", { src: "assets/icons/loading.gif", alt: "Loading", style: "width:30px; height:30px;" }),
            ]),
            el("div", { class: "large_button_container heading large", "data-lang-key": "next", role: "button", tabindex: "331", id: "btnSwapNext", onclick: () => { void onSwapNextClick(); } }, ["Next"]),
        ]),
    ]);
}

function buildSwapConfirmPanel(): HTMLElement {
    return el("div", { id: "divSwapConfirmPanel", class: "roundex-box scrollbar", style: SWAP_PANEL_STYLE }, [
        el("div", { class: "gas-header-row" }, [
            el("div", { class: "heading bold", "data-lang-key": "swap" }, ["Swap"]),
            el("div", { class: "gas-header-right" }, [
                el("span", { id: "spanSwapConfirmGasFee", class: "gas-fee-label" }),
                el("div", { id: "divSwapConfirmGasIcon", class: "gas-container", role: "button", tabindex: "344", onclick: () => onSwapConfirmGasIconClick() }),
            ]),
        ]),
        el("div", { class: "divider" }),
        el("div", { id: "divSwapConfirmLoading", style: "display: none; margin-top: 8px; margin-bottom: 8px;" }, [
            el("img", { src: "assets/icons/loading.gif", alt: "Loading", style: "width:30px; height:30px;" }),
        ]),
        el("div", { id: "divSwapSlippageRow", class: "input_container", style: "margin-top: 8px; display: none;" }, [
            el("div", { class: "heading medium", "data-lang-key": "slippage" }, ["Slippage"]),
            el("div", { style: "display: flex; align-items: center; gap: 8px;" }, [
                el("input", { class: "tab-name", type: "number", id: "txtSwapSlippage", min: "0", max: "100", step: "0.1", value: "1", style: "text-align: left; width: 60px; border: 1px solid #ccc; border-radius: 6px; padding: 6px;", tabindex: "333" }),
                el("span", {}, ["%"]),
            ]),
        ]),
        el("div", { id: "divSwapConfirmApprovalTxError", style: "display: none; margin-top: 8px; color: #c00; font-size: 0.9em;" }),
        el("div", { class: "input_container", style: "margin-top: 10px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "enter-wallet-password" }, ["Enter Wallet Password"]),
            el("div", { style: "display:flex; align-items:center; gap:8px;" }, [
                el("input", { type: "password", id: "pwdSwapConfirm", autocomplete: "off", placeholder: "Quantum Wallet Password", "data-placeholder-key": "password", style: SWAP_PWD_STYLE, tabindex: "337" }),
                passwordEye("pwdSwapConfirm", "338"),
            ]),
        ]),
        el("div", { style: "display: flex; align-items: center; justify-content: flex-end; gap: 10px; margin-top: 20px;" }, [
            el("div", { class: "large_button_container heading large", role: "button", tabindex: "339", id: "btnSwapConfirmNext", onclick: () => onSwapConfirmNextClick() }, ["Next"]),
        ]),
    ]);
}

function buildSwapRemoveAllowancePanel(): HTMLElement {
    return el("div", { id: "divSwapRemoveAllowancePanel", class: "roundex-box scrollbar", style: SWAP_PANEL_STYLE }, [
        el("div", { class: "gas-header-row" }, [
            el("div", { class: "heading bold", "data-lang-key": "remove-allowance-title" }, ["Remove allowance"]),
            el("div", { class: "gas-header-right" }, [
                el("span", { id: "spanRemoveAllowanceGasFee", class: "gas-fee-label" }),
                el("div", { id: "divRemoveAllowanceGasIcon", class: "gas-container", role: "button", tabindex: "345", onclick: () => onRemoveAllowanceGasIconClick() }),
            ]),
        ]),
        el("div", { class: "divider" }),
        el("div", { class: "input_container", style: "margin-top: 8px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "contract" }, ["Contract"]),
            el("a", { href: "#", id: "aRemoveAllowanceContract", style: "font-size: 0.9em; color: #0066cc; word-break: break-all; text-decoration: underline;", onclick: (event: Event) => { event.preventDefault(); void openRemoveAllowanceContractInExplorer(); } }, ["..."]),
        ]),
        el("div", { id: "divRemoveAllowanceError", style: "display: none; margin-top: 8px; color: #c00; font-size: 0.9em;" }),
        el("div", { class: "input_container", style: "margin-top: 10px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "enter-wallet-password" }, ["Enter Wallet Password"]),
            el("div", { style: "display:flex; align-items:center; gap:8px;" }, [
                el("input", { type: "password", id: "pwdRemoveAllowance", autocomplete: "off", placeholder: "Quantum Wallet Password", "data-placeholder-key": "password", style: SWAP_PWD_STYLE, tabindex: "338" }),
                passwordEye("pwdRemoveAllowance", "339"),
            ]),
        ]),
        el("div", { style: "display: flex; align-items: center; justify-content: flex-end; gap: 10px; margin-top: 20px;" }, [
            el("div", { class: "large_button_container heading large", role: "button", tabindex: "340", id: "btnRemoveAllowanceRemove", onclick: () => onRemoveAllowanceRemoveClick() }, [
                el("span", { "data-lang-key": "remove" }, ["Remove"]),
            ]),
        ]),
    ]);
}

function buildSwapAddAllowancePanel(): HTMLElement {
    return el("div", { id: "divSwapAddAllowancePanel", class: "roundex-box scrollbar", style: SWAP_PANEL_STYLE }, [
        el("div", { class: "gas-header-row" }, [
            el("div", { class: "heading bold", "data-lang-key": "add-allowance-title" }, ["Add allowance"]),
            el("div", { class: "gas-header-right" }, [
                el("span", { id: "spanAddAllowanceGasFee", class: "gas-fee-label" }),
                el("div", { id: "divAddAllowanceGasIcon", class: "gas-container", role: "button", tabindex: "346", onclick: () => onAddAllowanceGasIconClick() }),
            ]),
        ]),
        el("div", { class: "divider" }),
        el("div", { class: "input_container", style: "margin-top: 8px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "contract" }, ["Contract"]),
            el("a", { href: "#", id: "aAddAllowanceContract", style: "font-size: 0.9em; color: #0066cc; word-break: break-all; text-decoration: underline;", onclick: (event: Event) => { event.preventDefault(); void openAddAllowanceContractInExplorer(); } }, ["..."]),
        ]),
        el("div", { id: "divAddAllowanceQuantityRow", class: "input_container", style: "margin-top: 8px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "approval-quantity" }, ["Approval Quantity"]),
            el("div", { style: "display: flex; align-items: center; gap: 8px;" }, [
                el("input", { class: "tab-name", type: "number", id: "txtAddAllowanceQuantity", min: "0", step: "any", style: "text-align: left; width: 200px; border: 1px solid #ccc; border-radius: 6px; padding: 6px;", oninput: () => onAddAllowanceQuantityInput() }),
                el("a", { href: "#", "data-lang-key": "max", style: "color: #0066cc; cursor: pointer;", onclick: (event: Event) => { event.preventDefault(); setAddAllowanceQuantityToMax(); } }, ["Max"]),
            ]),
        ]),
        el("div", { id: "divAddAllowanceError", style: "display: none; margin-top: 8px; color: #c00; font-size: 0.9em;" }),
        el("div", { class: "input_container", style: "margin-top: 10px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "enter-wallet-password" }, ["Enter Wallet Password"]),
            el("div", { style: "display:flex; align-items:center; gap:8px;" }, [
                el("input", { type: "password", id: "pwdAddAllowance", autocomplete: "off", placeholder: "Quantum Wallet Password", "data-placeholder-key": "password", style: SWAP_PWD_STYLE, tabindex: "339" }),
                passwordEye("pwdAddAllowance", "340"),
            ]),
        ]),
        el("div", { style: "display: flex; align-items: center; justify-content: flex-end; gap: 10px; margin-top: 20px;" }, [
            el("div", { class: "large_button_container heading large", role: "button", tabindex: "341", id: "btnAddAllowanceAdd", onclick: () => onAddAllowanceAddClick() }, [
                el("span", { "data-lang-key": "add" }, ["Add"]),
            ]),
        ]),
    ]);
}

function buildSwapSuccessPanel(): HTMLElement {
    return el("div", { id: "divSwapSuccessPanel", class: "roundex-box scrollbar", style: SWAP_PANEL_STYLE }, [
        el("div", { class: "heading bold", "data-lang-key": "swap-succeeded", style: "color: green;" }, ["Swap transaction succeeded."]),
        el("div", { class: "divider" }),
        el("div", { class: "input_container", style: "margin-top: 8px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "swap-from-token" }, ["From token"]),
            el("span", { id: "spanSwapSuccessFromTokenDisplay", style: "font-size: 0.9em;" }),
        ]),
        el("div", { class: "input_container", style: "margin-top: 8px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "swap-to-token" }, ["To token"]),
            el("span", { id: "spanSwapSuccessToTokenDisplay", style: "font-size: 0.9em;" }),
        ]),
        el("div", { class: "input_container", style: "margin-top: 12px;" }, [
            el("table", { class: "styled-table", style: "width: 100%;" }, [
                el("thead", {}, [
                    el("tr", {}, [
                        el("th", { "data-lang-key": "token" }, ["Token"]),
                        el("th", { "data-lang-key": "before" }, ["Before"]),
                        el("th", { "data-lang-key": "after" }, ["After"]),
                    ]),
                ]),
                el("tbody", {}, [
                    el("tr", {}, [
                        el("td", { id: "tdSwapSuccessFromName" }),
                        el("td", { id: "tdSwapSuccessFromBefore" }),
                        el("td", { id: "tdSwapSuccessFromAfter" }),
                    ]),
                    el("tr", {}, [
                        el("td", { id: "tdSwapSuccessToName" }),
                        el("td", { id: "tdSwapSuccessToBefore" }),
                        el("td", { id: "tdSwapSuccessToAfter" }),
                    ]),
                ]),
            ]),
        ]),
        el("div", { class: "input_container", style: "margin-top: 12px;" }, [
            el("span", { class: "heading medium", "data-lang-key": "gas-fee-spent" }, ["Gas fee spent (coins)"]),
            el("span", { id: "spanSwapSuccessGasFee" }, ["0"]),
        ]),
        el("div", { style: "display: flex; justify-content: flex-end; margin-top: 20px;" }, [
            el("div", { class: "large_button_container heading large", role: "button", tabindex: "342", id: "btnSwapSuccessOk", style: "margin-left: auto;", onclick: () => onSwapSuccessOkClick() }, [
                el("span", { "data-lang-key": "ok" }, ["OK"]),
            ]),
        ]),
    ]);
}

function buildSwapScreen(): HTMLElement {
    return el("div", { class: "center-content home-content", id: "SwapScreen" }, [
        el("div", { class: "center-content-rounded-container", style: "width:93%;" }, [
            el("div", { class: "back-container", role: "button", tabindex: "320", id: "divBackSwapScreen", onclick: () => onSwapScreenBackClick() }),
            buildSwapMainPanel(),
            buildSwapConfirmPanel(),
            buildSwapRemoveAllowancePanel(),
            buildSwapAddAllowancePanel(),
            buildSwapSuccessPanel(),
        ]),
    ]);
}

export const swapScreenModule: ScreenModule = { parentId: "divMainContent", build: buildSwapScreen };
