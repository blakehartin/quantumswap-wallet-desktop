// Send and Offline-Sign screens, extracted 1:1 from the legacy fixture.
import { el } from "../ui/dom";
import type { ScreenModule } from "../ui/screens";
import { showWalletScreen, togglePasswordBox } from "../app/app";
import {
    copySignedSendTransaction,
    onSendGasIconClick,
    onToggleSendUnrecognized,
    openOfflineTxnSigningUrl,
    sendCoins,
    showSendScreen,
    signOfflineSend,
    updateInfoSendScreen,
} from "../app/send";

function buildSendScreen(): HTMLElement {
    return el("div", { class: "center-content home-content", id: "SendScreen" }, [
        el("div", { class: "center-content-rounded-container" }, [
            el("div", { class: "back-container", role: "button", tabindex: "300", onclick: () => { void showWalletScreen(); } }),
            el("div", { id: "divSendScreenInner", class: "roundex-box scrollbar", style: "padding-top: 15px; padding-bottom: 15px;overflow-y: auto;overflow-x: auto;" }, [
                el("div", { class: "gas-header-row" }, [
                    el("div", { class: "heading bold", "data-lang-key": "send" }, ["Send"]),
                    el("div", { class: "gas-header-right" }, [
                        el("span", { id: "spanSendGasFee", class: "gas-fee-label" }),
                        el("div", { id: "divSendGasIcon", class: "gas-container", role: "button", tabindex: "301", onclick: () => onSendGasIconClick() }),
                    ]),
                ]),
                el("div", { class: "divider" }),
                el("div", { class: "input_container", id: "divTokenList" }, [
                    el("div", { id: "divSendShowUnrecognized", style: "display:none; text-align:left; margin-bottom:8px;" }, [
                        el("input", { type: "checkbox", id: "chkSendShowUnrecognized", tabindex: "302", onchange: () => onToggleSendUnrecognized() }),
                        el("label", {
                            for: "chkSendShowUnrecognized", tabindex: "0", "data-lang-key": "show-unrecognized-tokens", style: "cursor: pointer; color:black;",
                            onkeydown: (event: Event) => {
                                const key = (event as KeyboardEvent).key;
                                if (key === "Enter" || key === " ") {
                                    event.preventDefault();
                                    (document.getElementById("chkSendShowUnrecognized") as HTMLInputElement).click();
                                }
                            },
                        }, ["Show unrecognized tokens"]),
                    ]),
                    el("div", { class: "selectwrapper" }, [
                        el("select", { id: "ddlCoinTokenToSend", class: "selectbox", tabindex: "303", onchange: () => { void updateInfoSendScreen(); } }, [
                            el("option", { value: "Q" }, ["Q"]),
                            el("option", { value: "Y2Q" }, ["Y2Q"]),
                            el("option", { value: "hei" }, ["Heisen"]),
                        ]),
                    ]),
                    el("input", {
                        class: "tab-name qs-input",
                        autocomplete: "off", id: "txtTokenContractAddress", name: "contract_address", "data-placeholder-key": "token-contract-address",
                        placeholder: "token contract address", tabindex: "304",
                    }),
                    el("div", { id: "divCoinTokenToSend", style: "font-size: small" }, ["0x0000000000000000000000000000000000000000000000000000000000001000"]),
                    el("div", { class: "divider" }),
                ]),
                el("div", { id: "divSendScreenBalanceBox" }, [
                    el("div", { class: "tab-name text-wallet-address", style: "text-align: left; font-weight: 200", "data-lang-key": "balance" }, ["Balance"]),
                    el("div", { class: "heading bold", style: "text-align: left; font-size: 20px; color:green;", id: "divBalanceSendScreen" }),
                    el("div", { class: "divider" }),
                ]),
                el("div", { class: "input_container" }, [
                    el("div", { class: "heading medium", "data-lang-key": "address-to-send" }, ["Address to send to"]),
                    el("input", {
                        class: "tab-name qs-input",
                        autocomplete: "off", id: "txtSendAddress", name: "send_address", "data-placeholder-key": "address-to-send",
                        placeholder: "Address to send to", tabindex: "305",
                    }),
                    el("div", { class: "divider" }),
                ]),
                el("div", { class: "input_container" }, [
                    el("div", { class: "heading medium", "data-lang-key": "quantity-to-send" }, ["Quantity to send"]),
                    el("input", {
                        class: "tab-name qs-input-strong",
                        type: "number", autocomplete: "off", id: "txtSendQuantity", name: "send_quantity", "data-placeholder-key": "quantity-to-send",
                        placeholder: "Quantity to send", tabindex: "306",
                    }),
                    el("div", { class: "divider" }),
                ]),
                el("div", { class: "input_container", id: "divCurrentNonce" }, [
                    el("div", { "data-lang-key": "nonce-help", style: "text-align: left;" }),
                    el("input", {
                        class: "tab-name qs-input-strong",
                        type: "number", autocomplete: "off", id: "txtCurrentNonce", name: "current_nonce", "data-placeholder-key": "current-nonce",
                        placeholder: "Current Nonce", tabindex: "307", maxlength: "6",
                    }),
                    el("div", { class: "divider" }),
                ]),
                el("div", { class: "input_container" }, [
                    el("div", { style: "width:100%;display:flex;align-items:center;" }, [
                        el("div", { style: "width: 80%;" }, [
                            el("input", {
                                class: "tab-name qs-input-strong",
                                type: "password", autocomplete: "off", id: "pwdSend", name: "password", "data-placeholder-key": "password",
                                placeholder: "Enter the password", tabindex: "308",
                            }),
                        ]),
                        el("div", {}, [
                            el("img", {
                                src: "assets/svg/eye-outline.svg", alt: "Show Password", class: "qs-eye",
                                "data-alt-key": "show-password", role: "button", tabindex: "309",
                                onclick: (event: Event) => togglePasswordBox(event.currentTarget as HTMLElement, "pwdSend"),
                            }),
                        ]),
                    ]),
                    el("div", { class: "divider" }),
                ]),
                el("div", { style: "display: flex; justify-content: flex-end;" }, [
                    el("div", { class: "large_button_container heading large", "data-lang-key": "send", role: "button", tabindex: "310", id: "btnSendCoins", onclick: () => { void sendCoins(); } }, ["Send"]),
                    el("div", { class: "large_button_container heading large", "data-lang-key": "sign-offline", role: "button", tabindex: "311", style: "margin-left:15px;", id: "btnOfflineSign", onclick: () => { void signOfflineSend(); } }, ["Offline Sign"]),
                ]),
            ]),
        ]),
    ]);
}

function buildOfflineSignScreen(): HTMLElement {
    return el("div", { class: "center-content home-content", id: "OfflineSignScreen" }, [
        el("div", { class: "center-content-rounded-container" }, [
            el("div", { class: "back-container", role: "button", tabindex: "3000", onclick: () => { void showSendScreen(); } }),
            el("div", { class: "tab-name", style: "color:black;" }, [
                el("p", {}, [
                    el("label", { "data-lang-key": "offline-txn-help" }, ["Copy the below signed transaction and submit it at: "]),
                    " ",
                    el("a", { href: "#", onclick: (event: Event) => { event.preventDefault(); void openOfflineTxnSigningUrl(); } }, ["https://QuantumCoin.org/offline-transaction-signing.html"]),
                ]),
            ]),
            el("div", { class: "roundex-box", style: "padding-top: 15px; padding-bottom: 15px;" }, [
                el("div", { class: "heading bold", "data-lang-key": "signed-transaction-details" }, ["Signed Transaction Details"]),
                el("div", { class: "divider" }),
                el("div", { class: "input_container" }, [
                    el("textarea", { id: "txtSignedSendTransaction", style: "width: 100%;", disabled: true, rows: "15", cols: "100", tabindex: "1" }),
                    el("div", { class: "copy-container", role: "button", style: "float:left;", id: "divCopySignedSendTransaction", tabindex: "2", onclick: () => { void copySignedSendTransaction(); } }),
                ]),
            ]),
        ]),
    ]);
}

export const sendScreenModules: ScreenModule[] = [
    { parentId: "divMainContent", build: buildSendScreen },
    { parentId: "divMainContent", build: buildOfflineSignScreen },
];
