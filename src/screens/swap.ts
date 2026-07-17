// Swap screen: main form plus the existing before/after success panel.
import { el } from "../ui/dom";
import type { ScreenModule } from "../ui/screens";
import {
    copySwapFromContractAddress,
    copySwapSuccessTransactionHash,
    copySwapToContractAddress,
    debouncedUpdateFromQuantityFromTo,
    debouncedUpdateToQuantityFromFrom,
    onSwapNextClick,
    onSwapScreenBackClick,
    onSwapSuccessOkClick,
    onToggleSwapUnrecognized,
    openSwapFromContractInExplorer,
    openSwapSuccessTransactionInExplorer,
    openSwapToContractInExplorer,
    setSwapFromQuantityToBalance,
    setSwapToQuantityToBalance,
    updateSwapScreenInfo,
} from "../app/swap";

const SWAP_PANEL_STYLE = "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto; max-height:590px; display: none;";

function buildSwapMainPanel(): HTMLElement {
    return el("div", { id: "divSwapScreenInner", class: "roundex-box scrollbar", style: "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto; max-height:690px;" }, [
        el("div", { class: "heading bold", "data-lang-key": "swap" }, ["Swap"]),
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
                el("div", { id: "divSwapFromContractRow", style: "font-size:0.85em; color:#372339; margin-top:4px; display:none; flex-direction:column; align-items:stretch; gap:4px;" }, [
                    el("div", { style: "display:flex; justify-content:flex-end; align-items:center; height:30px;" }, [
                        el("div", { class: "copy-container", role: "button", tabindex: "323", id: "divCopySwapFromContract", title: "Copy", onclick: () => { void copySwapFromContractAddress(); } }),
                        el("div", { class: "scan-container", role: "button", style: "margin-left:12px; margin-top:-2px;", tabindex: "324", title: "Block Explorer", onclick: () => { void openSwapFromContractInExplorer(); } }),
                    ]),
                    el("div", { id: "aSwapFromContract", style: "word-break:break-all; text-align:left;" }, ["..."]),
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
                el("div", { id: "divSwapToContractRow", style: "font-size:0.85em; color:#372339; margin-top:4px; display:none; flex-direction:column; align-items:stretch; gap:4px;" }, [
                    el("div", { style: "display:flex; justify-content:flex-end; align-items:center; height:30px;" }, [
                        el("div", { class: "copy-container", role: "button", tabindex: "328", id: "divCopySwapToContract", title: "Copy", onclick: () => { void copySwapToContractAddress(); } }),
                        el("div", { class: "scan-container", role: "button", style: "margin-left:12px; margin-top:-2px;", tabindex: "329", title: "Block Explorer", onclick: () => { void openSwapToContractInExplorer(); } }),
                    ]),
                    el("div", { id: "aSwapToContract", style: "word-break:break-all; text-align:left;" }, ["..."]),
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
        el("div", { class: "input_container", style: "margin-top:8px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "slippage" }, ["Slippage"]),
            el("div", { style: "display:flex; align-items:center; gap:8px;" }, [
                el("input", { class: "tab-name qs-input-strong", type: "number", id: "txtSwapSlippage", min: "0", max: "100", step: "0.1", value: "1", style: "width:100%;", tabindex: "331" }),
                el("span", {}, ["%"]),
            ]),
            el("div", { class: "divider" }),
        ]),
        el("div", { style: "display: flex; align-items: center; justify-content: flex-end; gap: 10px;margin-top:10px;" }, [
            el("div", { id: "divSwapQuoteLoading", style: "display: none;" }, [
                el("img", { src: "assets/icons/loading.gif", alt: "Loading", style: "width:30px; height:30px;" }),
            ]),
            el("div", { class: "large_button_container heading large", "data-lang-key": "next", role: "button", tabindex: "332", id: "btnSwapNext", onclick: () => { void onSwapNextClick(); } }, ["Next"]),
        ]),
    ]);
}

function buildSwapSuccessPanel(): HTMLElement {
    return el("div", { id: "divSwapSuccessPanel", class: "roundex-box scrollbar", style: SWAP_PANEL_STYLE }, [
        el("div", { class: "heading bold", "data-lang-key": "swap-succeeded", style: "color: green;" }, ["Swap transaction succeeded."]),
        el("div", { class: "divider" }),
        el("div", { class: "input_container", style: "margin-top:4px; gap:2px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "swap-from-token" }, ["From token"]),
            el("span", { id: "spanSwapSuccessFromTokenDisplay", style: "font-size: 0.9em;" }),
        ]),
        el("div", { class: "input_container", style: "margin-top:4px; gap:2px;" }, [
            el("div", { class: "heading medium", "data-lang-key": "swap-to-token" }, ["To token"]),
            el("span", { id: "spanSwapSuccessToTokenDisplay", style: "font-size: 0.9em;" }),
        ]),
        el("div", { class: "input_container scrollbar", style: "margin:12px auto 0; width:calc(100% - 20px); max-width:calc(100% - 20px); overflow-x:auto; overflow-y:hidden;" }, [
            el("table", { class: "styled-table", style: "width:100%; min-width:600px; text-align:left;" }, [
                el("thead", {}, [
                    el("tr", {}, [
                        el("th", { "data-lang-key": "token", style: "text-align:left; padding:6px 10px; line-height:1.2;" }, ["Token"]),
                        el("th", { "data-lang-key": "before", style: "text-align:left; padding:6px 10px; line-height:1.2;" }, ["Before"]),
                        el("th", { "data-lang-key": "after", style: "text-align:left; padding:6px 10px; line-height:1.2;" }, ["After"]),
                    ]),
                ]),
                el("tbody", {}, [
                    el("tr", {}, [
                        el("td", { id: "tdSwapSuccessFromName", style: "text-align:left;" }),
                        el("td", { id: "tdSwapSuccessFromBefore", style: "text-align:left;" }),
                        el("td", { id: "tdSwapSuccessFromAfter", style: "text-align:left;" }),
                    ]),
                    el("tr", {}, [
                        el("td", { id: "tdSwapSuccessToName", style: "text-align:left;" }),
                        el("td", { id: "tdSwapSuccessToBefore", style: "text-align:left;" }),
                        el("td", { id: "tdSwapSuccessToAfter", style: "text-align:left;" }),
                    ]),
                ]),
            ]),
        ]),
        el("div", { class: "input_container", style: "margin-top:8px; gap:2px;" }, [
            el("span", { class: "heading medium", "data-lang-key": "gas-fee-spent" }, ["Gas fee spent (coins)"]),
            el("span", { id: "spanSwapSuccessGasFee" }, ["0"]),
        ]),
        el("div", { id: "divSwapSuccessTxHashRow", style: "margin-top:8px; text-align:left;" }, [
            el("div", { style: "display:flex; align-items:center; justify-content:space-between;" }, [
                el("span", { class: "heading medium", "data-lang-key": "transaction-id" }, ["Transaction ID"]),
                el("div", { style: "display:flex; align-items:center; gap:12px;" }, [
                    el("div", { class: "copy-container", role: "button", tabindex: "340", title: "Copy", onclick: () => { void copySwapSuccessTransactionHash(); } }),
                    el("div", { class: "scan-container", role: "button", tabindex: "341", title: "Block Explorer", onclick: () => { void openSwapSuccessTransactionInExplorer(); } }),
                ]),
            ]),
            el("p", { id: "pSwapSuccessTxHash", style: "font-family:monospace; word-break:break-all; margin:2px 0 0;" }),
        ]),
        el("div", { style: "position:sticky; bottom:0; z-index:2; display:flex; justify-content:flex-end; margin-top:20px; padding:10px 0 4px; background:var(--panel, #0b0b12);" }, [
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
            buildSwapSuccessPanel(),
        ]),
    ]);
}

export const swapScreenModule: ScreenModule = { parentId: "divMainContent", build: buildSwapScreen };
