// Validator screen, extracted 1:1 from the legacy fixture.
import { el } from "../ui/dom";
import type { ScreenModule } from "../ui/screens";
import { showSettingsScreen, togglePasswordBox } from "../app/app";
import {
    onValidatorGasIconClick,
    openValidatorPage,
    updateValidatorScreen,
    validation,
} from "../app/validator";

function buildValidatorScreen(): HTMLElement {
    return el("div", { class: "center-content home-content", id: "ValidatorScreen" }, [
        el("div", { class: "center-content-rounded-container" }, [
            el("div", { class: "back-container", role: "button", tabindex: "2308", onclick: () => showSettingsScreen() }),
            el("div", { class: "roundex-box scrollbar", style: "padding-top: 15px; padding-bottom: 15px;overflow-y: auto;overflow-x: auto;" }, [
                el("div", { class: "gas-header-row" }, [
                    el("div", { class: "heading bold", "data-lang-key": "validator" }, ["Validator"]),
                    el("div", { class: "gas-header-right" }, [
                        el("span", { id: "spanValidatorGasFee", class: "gas-fee-label" }),
                        el("div", { id: "divValidatorGasIcon", class: "gas-container", role: "button", tabindex: "2310", onclick: () => onValidatorGasIconClick() }),
                    ]),
                ]),
                el("div", { class: "tab-name", style: "color:black;" }, [
                    el("div", { class: "divider" }),
                    el("label", { "data-lang-key": "validator-help", style: "margin-top:5px" }, [
                        "Use the following options to manage your validation. Use these options only if you want to run a validator node or if you are already running one.\n                                    You can check your validation status at: ",
                    ]),
                    el("a", { href: "#", id: "ahrefValidatorPage", tabindex: "2309", onclick: (event: Event) => { event.preventDefault(); openValidatorPage(); } }, ["link here"]),
                ]),
                el("div", { class: "input_container", id: "divValidatorOptions" }, [
                    el("div", { class: "selectwrapper" }, [
                        el("select", { id: "ddlValidatorOptions", class: "selectbox", tabindex: "2300", onchange: () => { void updateValidatorScreen(); } }, [
                            el("option", { value: "none" }, ["(select an option)"]),
                            el("option", { value: "newdeposit" }, ["New Validator Deposit"]),
                            el("option", { value: "increasedeposit" }, ["Increase Deposit"]),
                            el("option", { value: "initiatepartialwithdrawal" }, ["Initiate Partial Withdrawal"]),
                            el("option", { value: "completepartialwithdrawal" }, ["Complete Partial Withdrawal"]),
                            el("option", { value: "pausevalidation" }, ["Pause Validation"]),
                            el("option", { value: "resumevalidation" }, ["Resume Validation"]),
                        ]),
                    ]),
                ]),
                el("div", { class: "input_container", id: "divValidatorAddress" }, [
                    el("div", { class: "heading medium", "data-lang-key": "validator-address" }, ["Validator Address"]),
                    el("input", {
                        class: "tab-name qs-input",
                        autocomplete: "off", id: "txtValidatorAddress", name: "validator_address", "data-placeholder-key": "validator-address",
                        placeholder: "Validator Address", tabindex: "2301",
                    }),
                    el("div", { class: "divider" }),
                ]),
                el("div", { class: "input_container", id: "divValidatorDepositCoins" }, [
                    el("div", { class: "heading medium", "data-lang-key": "quantity" }, ["Quantity"]),
                    el("input", {
                        class: "tab-name qs-input-strong",
                        type: "number", autocomplete: "off", id: "txtValidatorDepositCoins", name: "validator_deposit_coins", "data-placeholder-key": "quantity",
                        placeholder: "Quantity", tabindex: "2302",
                    }),
                    el("div", { class: "divider" }),
                ]),
                el("div", { class: "input_container", id: "divCurrentNonceValidator" }, [
                    el("div", { "data-lang-key": "nonce-help", style: "text-align: left;" }),
                    el("input", {
                        class: "tab-name qs-input-strong",
                        type: "number", autocomplete: "off", id: "txtCurrentNonceValidator", name: "current_nonce_validator", "data-placeholder-key": "current-nonce",
                        placeholder: "Current Nonce", tabindex: "2303", maxlength: "6",
                    }),
                    el("div", { class: "divider" }),
                ]),
                el("div", { class: "input_container", id: "divValidatorScreenPassword" }, [
                    el("div", { class: "heading medium", "data-lang-key": "enter-wallet-password", style: "margin-top:5px" }, ["Enter Wallet Password"]),
                    el("div", { style: "width:100%;margin-top:5px;display:flex;align-items:center;" }, [
                        el("div", { style: "width: 80%;" }, [
                            el("input", {
                                class: "tab-name qs-input-strong",
                                type: "password", autocomplete: "off", id: "pwdValidator", name: "password", "data-placeholder-key": "password",
                                placeholder: "password", tabindex: "2304",
                            }),
                        ]),
                        el("div", {}, [
                            el("img", {
                                src: "assets/svg/eye-outline.svg", alt: "Show Password", class: "qs-eye",
                                "data-alt-key": "show-password", role: "button", tabindex: "2305",
                                onclick: (event: Event) => togglePasswordBox(event.currentTarget as HTMLElement, "pwdValidator"),
                            }),
                        ]),
                    ]),
                    el("div", { class: "divider" }),
                ]),
                el("div", { class: "divider" }),
                el("div", { style: "display: flex; justify-content: flex-end;", id: "divValidatorButton" }, [
                    el("div", { class: "large_button_container heading large", "data-lang-key": "submit", role: "button", tabindex: "2306", id: "btnValidation", style: "float:right;", onclick: () => validation() }, ["Submit"]),
                    el("div", { class: "large_button_container heading large", "data-lang-key": "sign-offline", role: "button", tabindex: "2307", style: "margin-left:15px;float:right;", id: "btnOfflineValidation", onclick: () => validation() }, ["Offline Sign"]),
                ]),
            ]),
        ]),
    ]);
}

export const validatorScreenModule: ScreenModule = { parentId: "divMainContent", build: buildValidatorScreen };
