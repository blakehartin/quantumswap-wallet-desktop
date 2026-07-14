// GENERATED FILE - do not edit by hand.
// Produced by scripts/generate-views.mjs from the legacy index.html.
// Rebuilds the legacy <body> DOM 1:1 (same elements, attribute order,
// whitespace text nodes and comments) so styles.css renders identically.
// Inline on*-handlers from the legacy HTML are bound through the typed
// handler registry (see src/app/handlers.ts) via w().

import { e, w, c, t } from "./render";

export function buildAppBody(): Node[] {
    return [
        t("\n"),
        e("template", [["id", "tplBlockchainNetworkRow"]], [
            "\n    ",
            e("tr", [["class", "network-row"]], [
                "\n        ",
                e("td", [], [
                    "[BLOCKCHAIN_NETWORK_ID]",
                ]),
                "\n        ",
                e("td", [], [
                    "[BLOCKCHAIN_NETWORK_NAME]",
                ]),
                "\n        ",
                e("td", [], [
                    "[BLOCKCHAIN_SCAN_API_URL]",
                ]),
                "\n        ",
                e("td", [], [
                    "[BLOCKCHAIN_EXPLORER_API_URL]",
                ]),
                "\n        ",
                e("td", [], [
                    "[BLOCKCHAIN_RPC_ENDPOINT_URL]",
                ]),
                "\n    ",
            ]),
            "\n",
        ], true),
        t("\n"),
        e("dialog", [["id", "modalEulaDialog"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n    ",
            e("div", [["class", "modal-content"]], [
                "\n        ",
                e("div", [["style", "margin-bottom:30px;"]], [
                    "\n            ",
                    e("div", [["id", "divEula"]], [
                        "\n                ",
                        e("p", [], [
                            "hello world",
                        ]),
                        "\n                ",
                        e("p", [], [
                            "hello world",
                        ]),
                        "\n                ",
                        e("p", [], [
                            "hello world",
                        ]),
                        "\n            ",
                    ]),
                    "\n            ",
                    e("div", [["style", "margin-top:20px;"]], [
                        "\n                ",
                        e("div", [["class", "iagree"], ["data-lang-key", "i-agree"], ["role", "button"], ["tabindex", "2"], ["id", "divIAgree"]], [
                            "\n                    I Agree\n                ",
                        ]),
                        "\n            ",
                    ]),
                    "\n        ",
                ]),
                "\n    ",
            ]),
            "\n",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalOkDialog"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"]], [
                "\n            ",
                e("div", [["style", "float:left;display:none;"], ["id", "divSuccess"]], [
                    e("img", [["src", "assets/svg/checkmark-circle-outline.svg"], ["style", "width:55px;margin-top:12px;"], ["alt", "Success"]], []),
                ]),
                "\n            ",
                e("div", [["style", "float:left;display:none;"], ["id", "divWarn"]], [
                    e("img", [["src", "assets/svg/warning-outline.svg"], ["style", "width:55px;margin-top:12px;"], ["alt", "Warning"]], []),
                ]),
                "\n            ",
                e("div", [["style", "margin-bottom:10px;"]], [
                    "\n                ",
                    e("div", [["style", "padding-bottom:20px;overflow:auto;"]], [
                        e("p", [["id", "pDetails"], ["class", "scrollbar"], ["tabindex", "2"]], [
                            "Some text in the Modal..",
                        ]),
                    ]),
                    "\n                ",
                    e("div", [["style", "display:flex; justify-content:flex-end;"]], [
                        "\n                    ",
                        e("button", [["class", "close"], ["data-lang-key", "ok"], ["role", "button"], ["tabindex", "1"], ["id", "divModalOk"]], [
                            "\n                        Ok\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalConfirmDialog"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"]], [
                "\n            ",
                e("div", [["style", "margin-bottom:30px;"]], [
                    "\n                ",
                    e("div", [], [
                        e("p", [["id", "pDetailsConfirm"], ["style", "font-weight:bold;overflow:auto"], ["class", "scrollbar"], ["tabindex", "4"]], [
                            "Some text in the Modal..",
                        ]),
                    ]),
                    "\n                ",
                    e("div", [], [
                        "\n                    ",
                        e("label", [["data-lang-key", "network"]], [
                            "Network",
                        ]),
                        " : ",
                        e("label", [["style", "color:green"], ["id", "lblNetworkConfirm"]], []),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("div", [], [
                        "\n                    ",
                        e("label", [["data-lang-key", "type-the-words"]], [
                            "Type the words",
                        ]),
                        " ",
                        e("span", [["style", "color:blue"]], [
                            "i agree",
                        ]),
                        "\n                    ",
                        e("input", [["type", "text"], ["style", "width:63px;font-size:16px;border-radius:10px;border:1px solid;padding:3px;"], ["id", "txtConfirm"], ["tabindex", "1"]], []),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("div", [["style", "margin-top:20px;"]], [
                        "\n                    ",
                        e("div", [["class", "proceed"], ["data-lang-key", "ok"], ["role", "button"], ["tabindex", "3"]], [
                            "\n                        Ok\n                    ",
                        ]),
                        "\n                    ",
                        e("button", [["class", "cancel"], ["data-lang-key", "cancel"], ["role", "button"], ["tabindex", "2"]], [
                            "\n                        Cancel\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalYesNoDialog"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"]], [
                "\n            ",
                e("div", [["style", "margin-bottom:20px;"]], [
                    "\n                ",
                    e("p", [["id", "pDetailsYesNo"], ["style", "font-weight:bold;overflow:auto"], ["class", "scrollbar"], ["tabindex", "4"]], []),
                    "\n                ",
                    e("div", [["style", "margin-top:20px;display:flex;gap:15px;justify-content:center;"]], [
                        "\n                    ",
                        e("button", [["class", "cancel"], ["data-lang-key", "no"], ["role", "button"], ["tabindex", "2"], ["id", "btnYesNoNo"]], [
                            "No",
                        ]),
                        "\n                    ",
                        e("button", [["class", "proceed"], ["data-lang-key", "yes"], ["role", "button"], ["tabindex", "1"], ["id", "btnYesNoYes"]], [
                            "Yes",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalNetworkDialog"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"]], [
                "\n            ",
                e("div", [["style", "margin-bottom:10px;"]], [
                    "\n                ",
                    e("h3", [["data-lang-key", "select-network"]], [
                        "Select Network",
                    ]),
                    "\n                ",
                    e("div", [["id", "divNetworkListDialog"]], [
                        "\n                    ",
                        e("div", [["style", "padding-bottom:20px;"], ["class", "network-template"]], [
                            "\n                        ",
                            e("label", [["class", "tab-label"], ["style", "text-align: left;"]], [
                                "\n                            ",
                                e("input", [["type", "radio"], ["name", "network_option"], ["value", "[BLOCKCHAIN_NETWORK_INDEX]"], ["class", "safety_quiz_option"], ["id", "optNetwork[BLOCKCHAIN_NETWORK_INDEX]"], ["tabindex", "[TAB_INDEX]"]], []),
                                "\n                            [BLOCKCHAIN_NETWORK_NAME] (NetworkId [BLOCKCHAIN_NETWORK_ID])\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("button", [["class", "oknetwork"], ["data-lang-key", "ok"], ["role", "button"], ["id", "divOkNetwork"], ["tabindex", "2"]], [
                        "Ok",
                    ]),
                    "\n                ",
                    e("button", [["class", "cancel"], ["data-lang-key", "cancel"], ["role", "button"], ["id", "divCancelNetwork"], ["tabindex", "1"]], [
                        "Cancel",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalOfflineTxnSigning"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"]], [
                "\n            ",
                e("div", [["style", "margin-bottom:10px;"]], [
                    "\n                ",
                    e("h3", [["data-lang-key", "offline-txn-signing"]], [
                        "Offline Transaction Signing",
                    ]),
                    "\n                ",
                    e("div", [["style", "margin-bottom:20px;"]], [
                        "\n                    ",
                        e("label", [["data-lang-key", "help"], ["style", "cursor: pointer;"]], [
                            "Help",
                        ]),
                        ": ",
                        w(e("a", [["href", "#"]], [
                            "QuantumCoin.org/offline-transaction-signing.html",
                        ]), "click", "return openOfflineTxnSigningUrl();"),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("div", [["id", "divOfflineTxnSigning"]], [
                        "\n                    ",
                        e("div", [["style", "padding-bottom:20px;"], ["class", "network-template"]], [
                            "\n                        ",
                            e("form", [["id", "offlineTxnSigningForm"], ["style", "display: flex; flex-direction: column; gap: 10px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left;cursor:pointer;"], ["role", "button"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "optOfflineTxnSigning"], ["value", "enabled"], ["class", "safety_quiz_option"], ["id", "optOfflineTxnSigningEnabled"], ["tabindex", "2"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "enabled"], ["style", "cursor: pointer;"]], [
                                        "Enabled",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optOfflineTxnSigningEnabled').checked  = true;"),
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left;cursor:pointer;"], ["role", "button"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "optOfflineTxnSigning"], ["value", "disabled"], ["class", "safety_quiz_option"], ["id", "optOfflineTxnSigningDisabled"], ["tabindex", "3"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "disabled"], ["style", "cursor: pointer;"]], [
                                        "Disabled",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optOfflineTxnSigningDisabled').checked  = true;"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("button", [["class", "oknetwork"], ["data-lang-key", "ok"], ["role", "button"], ["id", "btnOkOfflineTxnSigning"], ["tabindex", "4"]], [
                        "Ok",
                    ]),
                    "\n                ",
                    e("button", [["class", "cancel"], ["data-lang-key", "cancel"], ["role", "button"], ["id", "btnCancelOfflineTxnSigning"], ["tabindex", "1"]], [
                        "Cancel",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalAdvancedSigning"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"]], [
                "\n            ",
                e("div", [["style", "margin-bottom:10px;"]], [
                    "\n                ",
                    e("h3", [["data-lang-key", "signing"]], [
                        "Signing",
                    ]),
                    "\n                ",
                    e("div", [["style", "margin-bottom:20px;"]], [
                        "\n                    ",
                        e("p", [["data-lang-key", "advanced-signing-description"]], [
                            "Applicable wallets will incur 30 times higher gas price if this setting is enabled",
                        ]),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("div", [["id", "divAdvancedSigning"]], [
                        "\n                    ",
                        e("div", [["style", "padding-bottom:20px;"], ["class", "network-template"]], [
                            "\n                        ",
                            e("form", [["id", "advancedSigningForm"], ["style", "display: flex; flex-direction: column; gap: 10px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left;cursor:pointer;"], ["role", "button"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "optAdvancedSigning"], ["value", "enabled"], ["class", "safety_quiz_option"], ["id", "optAdvancedSigningEnabled"], ["tabindex", "2"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "advanced-signing-option"], ["style", "cursor: pointer;"]], [
                                        "Enable advanced signing (may incur 30 times higher gas price)",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optAdvancedSigningEnabled').checked  = true;"),
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left;cursor:pointer;"], ["role", "button"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "optAdvancedSigning"], ["value", "disabled"], ["class", "safety_quiz_option"], ["id", "optAdvancedSigningDisabled"], ["tabindex", "3"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "disabled"], ["style", "cursor: pointer;"]], [
                                        "Disabled",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optAdvancedSigningDisabled').checked  = true;"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("button", [["class", "oknetwork"], ["data-lang-key", "ok"], ["role", "button"], ["id", "btnOkAdvancedSigning"], ["tabindex", "4"]], [
                        "Ok",
                    ]),
                    "\n                ",
                    e("button", [["class", "cancel"], ["data-lang-key", "cancel"], ["role", "button"], ["id", "btnCancelAdvancedSigning"], ["tabindex", "1"]], [
                        "Cancel",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalWaitDialog"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"]], [
                "\n            ",
                e("div", [["style", "float:left;"], ["id", "divLoadingModalIcon"]], [
                    e("img", [["src", "assets/icons/loading.gif"], ["style", "width:70px;margin-top:12px;margin-right:10px;"], ["alt", "Loading"]], []),
                ]),
                "\n            ",
                e("div", [["style", "margin-bottom:10px;"]], [
                    "\n                ",
                    e("div", [["style", "padding-bottom:20px;"]], [
                        e("p", [["id", "pWaitDetails"], ["class", "scrollbar"], ["style", "overflow:auto;"], ["tabindex", "1"]], [
                            "Some text in the Modal..",
                        ]),
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalOfflineSignature"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"]], [
                "\n            ",
                e("div", [["style", "margin-bottom:10px;"]], [
                    "\n                ",
                    e("h3", [["data-lang-key", "offline-txn-signing"]], [
                        "Offline Transaction Signing",
                    ]),
                    "\n                ",
                    e("div", [["style", "margin-bottom:20px;"]], [
                        "\n                    ",
                        e("p", [], [
                            "\n                        ",
                            e("label", [["data-lang-key", "offline-txn-help"]], [
                                "Copy the below signed transaction and submit it at: ",
                            ]),
                            " ",
                            w(e("a", [["tabindex", "4"], ["href", "#"]], [
                                "https://QuantumCoin.org/offline-transaction-signing.html",
                            ]), "click", "return openOfflineTxnSigningUrl();"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("div", [["id", "divOfflineSignature"]], [
                        "\n                    ",
                        e("div", [["style", "padding-bottom:20px;"], ["class", "network-template"]], [
                            "\n                           ",
                            e("textarea", [["id", "txtOfflineSignature"], ["style", "width: 100%;"], ["disabled", ""], ["rows", "15"], ["cols", "100"], ["tabindex", "1"]], [
                                "\n                           ",
                            ]),
                            "\n                        ",
                            w(e("div", [["class", "copy-container"], ["role", "button"], ["style", "float:left;"], ["id", "divOfflineSignatureCopy"], ["tabindex", "2"]], []), "click", "copyOfflineSignature()"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("button", [["class", "oknetwork"], ["data-lang-key", "ok"], ["role", "button"], ["id", "btnOkOfflineSignature"], ["tabindex", "3"]], [
                        "Ok",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalTransactionReview"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"], ["style", "overflow:hidden;"]], [
            "\n        ",
            e("div", [["class", "modal-content"], ["style", "margin:8% auto; max-height:84vh; display:flex; flex-direction:column; overflow:hidden;"]], [
                "\n                ",
                e("p", [["id", "pTxReviewPrompt"], ["style", "font-weight:bold;overflow:auto;"], ["class", "scrollbar"], ["data-lang-key", "review-transaction-prompt"], ["tabindex", "4"]], [
                    "Please review your transaction request to be sent:",
                ]),
                "\n                ",
                e("div", [["class", "scrollbar"], ["style", "overflow:auto; flex:1 1 auto; min-height:0;"]], [
                    "\n                    ",
                    e("div", [["style", "margin-top:8px;"]], [
                        "\n                        ",
                        e("label", [["id", "lblTxReviewAsset"], ["data-lang-key", "what-is-being-sent"], ["style", "font-weight:bold;display:block;"]], [
                            "What is being sent",
                        ]),
                        "\n                        ",
                        e("span", [["id", "spanTxReviewAsset"], ["style", "word-break:break-all;"]], []),
                        "\n                    ",
                    ]),
                    "\n                    ",
                    e("div", [["id", "rowTxReviewContract"], ["style", "margin-top:8px;display:none;"]], [
                        "\n                        ",
                        e("label", [["data-lang-key", "contract-address"], ["style", "font-weight:bold;display:block;"]], [
                            "Contract address",
                        ]),
                        "\n                        ",
                        e("span", [["id", "spanTxReviewContract"], ["style", "word-break:break-all;"]], []),
                        "\n                    ",
                    ]),
                    "\n                    ",
                    e("div", [["style", "margin-top:8px;"]], [
                        "\n                        ",
                        e("label", [["data-lang-key", "from-address"], ["style", "font-weight:bold;display:block;"]], [
                            "From Address",
                        ]),
                        "\n                        ",
                        e("span", [["id", "spanTxReviewFrom"], ["style", "word-break:break-all;"]], []),
                        "\n                    ",
                    ]),
                    "\n                    ",
                    e("div", [["style", "margin-top:8px;"]], [
                        "\n                        ",
                        e("label", [["data-lang-key", "to-address"], ["style", "font-weight:bold;display:block;"]], [
                            "To Address",
                        ]),
                        "\n                        ",
                        e("span", [["id", "spanTxReviewTo"], ["style", "word-break:break-all;"]], []),
                        "\n                    ",
                    ]),
                    "\n                    ",
                    e("div", [["style", "margin-top:8px;"]], [
                        "\n                        ",
                        e("label", [["id", "lblTxReviewQuantity"], ["data-lang-key", "send-quantity"], ["style", "font-weight:bold;"]], [
                            "Quantity",
                        ]),
                        " : ",
                        e("span", [["id", "spanTxReviewQuantity"], ["style", "word-break:break-all;"]], []),
                        "\n                    ",
                    ]),
                    "\n                    ",
                    e("div", [["style", "margin-top:8px;"]], [
                        "\n                        ",
                        e("label", [["data-lang-key", "gas-limit"], ["style", "font-weight:bold;"]], [
                            "Gas limit (gas-units)",
                        ]),
                        " : ",
                        e("span", [["id", "spanTxReviewGasLimit"]], []),
                        "\n                    ",
                    ]),
                    "\n                    ",
                    e("div", [["style", "margin-top:8px;"]], [
                        "\n                        ",
                        e("label", [["data-lang-key", "gas-fee"], ["style", "font-weight:bold;"]], [
                            "Estimated gas fee (coins)",
                        ]),
                        " : ",
                        e("span", [["id", "spanTxReviewGasFee"]], []),
                        "\n                    ",
                    ]),
                    "\n                    ",
                    e("div", [["id", "rowTxReviewNonce"], ["style", "margin-top:8px;display:none;"]], [
                        "\n                        ",
                        e("label", [["data-lang-key", "current-nonce"], ["style", "font-weight:bold;"]], [
                            "Current Nonce",
                        ]),
                        " : ",
                        e("span", [["id", "spanTxReviewNonce"]], []),
                        "\n                    ",
                    ]),
                    "\n                    ",
                    e("div", [["style", "margin-top:8px;"]], [
                        "\n                        ",
                        e("label", [["data-lang-key", "network"], ["style", "font-weight:bold;"]], [
                            "Network",
                        ]),
                        " : ",
                        e("span", [["id", "spanTxReviewNetwork"], ["style", "color:green;"]], []),
                        "\n                    ",
                    ]),
                    "\n                ",
                ]),
                "\n                ",
                e("div", [["style", "margin-top:12px;"]], [
                    "\n                    ",
                    e("label", [["data-lang-key", "type-i-agree-to-confirm"]], [
                        "Type ",
                    ]),
                    " ",
                    e("span", [["style", "color:blue"], ["data-lang-key", "i-agree-literal"]], [
                        "i agree",
                    ]),
                    e("label", [["data-lang-key", "type-i-agree-to-confirm-suffix"]], [
                        " to confirm:",
                    ]),
                    "\n                    ",
                    e("input", [["type", "text"], ["style", "width:63px;font-size:16px;border-radius:10px;border:1px solid;padding:3px;"], ["id", "txtTxReviewIAgree"], ["tabindex", "1"]], []),
                    "\n                ",
                ]),
                "\n                ",
                e("div", [["id", "rowTxReviewPassword"], ["style", "margin-top:12px;display:flex;align-items:center;gap:6px;"]], [
                    "\n                    ",
                    e("label", [["data-lang-key", "enter-wallet-password"]], [
                        "Password",
                    ]),
                    "\n                    ",
                    e("input", [["type", "password"], ["style", "width:100%;max-width:200px;font-size:16px;border-radius:10px;border:1px solid;padding:3px;"], ["id", "txtTxReviewPassword"], ["tabindex", "5"], ["autocomplete", "off"]], []),
                    "\n                    ",
                    w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;flex-shrink:0;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "6"], ["title", "Show/Hide password"]], []), "click", "togglePasswordBox(this, 'txtTxReviewPassword');"),
                    "\n                ",
                ]),
                "\n                ",
                e("div", [["style", "margin-top:25px;display:flex;gap:15px;justify-content:flex-end;"]], [
                    "\n                    ",
                    e("button", [["class", "cancel"], ["data-lang-key", "cancel"], ["role", "button"], ["tabindex", "3"], ["id", "btnTxReviewCancel"]], [
                        "Cancel",
                    ]),
                    "\n                    ",
                    e("button", [["class", "proceed"], ["data-lang-key", "ok"], ["role", "button"], ["tabindex", "2"], ["id", "btnTxReviewSubmit"]], [
                        "Ok",
                    ]),
                    "\n                ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("dialog", [["id", "modalGasConfig"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"], ["style", "margin:10% auto; max-width:460px;"]], [
                "\n            ",
                e("h3", [["data-lang-key", "gas"], ["style", "margin-top:0;"]], [
                    "Gas",
                ]),
                "\n            ",
                e("div", [["class", "input_container"], ["style", "margin-top:10px;"]], [
                    "\n                ",
                    e("div", [["class", "heading medium"], ["data-lang-key", "gas-limit"]], [
                        "Gas limit (gas-units)",
                    ]),
                    "\n                ",
                    e("input", [["class", "tab-name"], ["type", "number"], ["min", "0"], ["step", "1"], ["id", "txtGasLimit"], ["style", "text-align: left; width: 100%; border: 1px solid #ccc; border-radius: 6px; padding: 6px;"], ["tabindex", "1"]], []),
                    "\n            ",
                ]),
                "\n            ",
                e("div", [["class", "input_container"], ["style", "margin-top:10px;"]], [
                    "\n                ",
                    e("div", [["class", "heading medium"], ["data-lang-key", "gas-fee"]], [
                        "Estimated gas fee (coins)",
                    ]),
                    "\n                ",
                    e("input", [["class", "tab-name"], ["type", "text"], ["id", "txtGasFee"], ["readonly", ""], ["style", "text-align: left; width: 100%; border: 1px solid #ccc; border-radius: 6px; padding: 6px;"], ["tabindex", "2"]], []),
                    "\n            ",
                ]),
                "\n            ",
                e("div", [["style", "margin-top:20px; display:flex; gap:15px; justify-content:flex-end;"]], [
                    "\n                ",
                    e("button", [["class", "cancel"], ["data-lang-key", "cancel"], ["role", "button"], ["tabindex", "4"], ["id", "btnGasConfigCancel"]], [
                        "Cancel",
                    ]),
                    "\n                ",
                    e("button", [["class", "proceed"], ["data-lang-key", "ok"], ["role", "button"], ["tabindex", "3"], ["id", "btnGasConfigOk"]], [
                        "Ok",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("div", [["id", "divGasToast"], ["class", "gas-toast"], ["role", "status"], ["aria-live", "polite"]], []),
        t("\n\n    "),
        e("dialog", [["id", "modalSendCompleted"], ["class", "modal"], ["tabindex", "-1"], ["role", "dialog"]], [
            "\n        ",
            e("div", [["class", "modal-content"], ["style", "margin:10% auto; max-width:520px;"]], [
                "\n            ",
                e("p", [["id", "pSendCompletedMessage"], ["style", "margin:0;"]], []),
                "\n            ",
                e("div", [["style", "margin-top:16px;"]], [
                    "\n                ",
                    e("div", [["style", "display:flex; align-items:center; justify-content:space-between;"]], [
                        "\n                    ",
                        e("label", [["data-lang-key", "transaction-id"], ["style", "font-weight:bold;"]], [
                            "Transaction ID",
                        ]),
                        "\n                    ",
                        e("div", [["style", "display:flex; align-items:center; gap:12px;"]], [
                            "\n                        ",
                            e("div", [["class", "copy-container"], ["role", "button"], ["id", "divSendCompletedCopy"], ["title", "Copy"], ["tabindex", "2"]], []),
                            "\n                        ",
                            e("div", [["class", "scan-container"], ["role", "button"], ["id", "divSendCompletedExplorer"], ["title", "Block Explorer"], ["tabindex", "3"]], []),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n                ",
                    e("p", [["id", "pSendCompletedTxHash"], ["style", "font-family:monospace; word-break:break-all; margin-top:4px;"]], []),
                    "\n                ",
                    e("div", [["id", "divSendCompletedStatus"], ["style", "display:flex; align-items:center; gap:10px; margin-top:12px;"]], [
                        "\n                    ",
                        e("img", [["id", "imgSendCompletedStatus"], ["src", "assets/icons/loading.gif"], ["alt", "Loading"], ["style", "width:30px; height:30px; flex-shrink:0;"]], []),
                        "\n                    ",
                        e("span", [["id", "spanSendCompletedStatus"], ["style", "font-size:0.9em;"]], []),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n            ",
                e("div", [["style", "margin-top:20px; display:flex; justify-content:flex-end;"]], [
                    "\n                ",
                    e("button", [["class", "proceed"], ["data-lang-key", "ok"], ["role", "button"], ["tabindex", "1"], ["id", "btnSendCompletedOk"]], [
                        "Ok",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("div", [["style", "margin: -10px;"]], [
            "\n        ",
            w(e("div", [["class", "dropdown"], ["id", "divNetworkDropdown"], ["role", "button"], ["tabindex", "1000"], ["style", "display:none;"]], [
                "\n            ",
                e("div", [["style", "width:fit-content;margin-top:4px;float:left;"]], [
                    e("span", [["class", "networkbox"], ["id", "spnNetwork"]], [
                        "MAINNET▼",
                    ]),
                ]),
                "\n        ",
            ]), "click", "return showNetworkDialog();"),
            "\n\n        ",
            e("div", [["class", "gradient"], ["id", "gradient"]], [
                "\n            ",
                e("div", [["class", "logo"]], [
                    "\n                ",
                    e("img", [["src", "assets/icons/app/dp.png"], ["alt", "Title"], ["class", "logoimg"], ["id", "imgLogo"]], []),
                    "\n            ",
                ]),
                "\n            ",
                e("div", [["class", "animate-character"], ["id", "divWalletTitle"], ["data-lang-key", "title"]], [
                    "Title",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("div", [["class", "tabs-content"], ["id", "login-content"], ["style", "display: none;"]], [
            "\n\n        ",
            e("div", [["class", "content"], ["id", "unlockScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [["class", "heading large"], ["data-lang-key", "unlock-wallet"]], [
                                "Unlock Wallet",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "enter-wallet-password"]], [
                                    "Password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["style", "float: left; width: 80%;"]], [
                                        "\n                                    ",
                                        e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdUnlock"], ["name", "password"], ["data-placeholder-key", "password"], ["placeholder", "Enter a password"], ["tabindex", "1"], ["autofocus", ""]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "float:left"]], [
                                        "\n                                    ",
                                        w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "2"]], []), "click", "togglePasswordBox(this, 'pwdUnlock');"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "unlock"], ["role", "button"], ["tabindex", "3"]], [
                                "\n                            Unlock\n                        ",
                            ]), "click", "unlockWallet();"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "welcomeScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        e("div", [["class", "roundex-box"]], [
                            "\n                        ",
                            e("div", [["id", "welcomeText"], ["class", "heading bold large"]], []),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["id", "infoContainer"]], [
                                "\n                            ",
                                e("div", [["class", "heading bold medium"], ["id", "divInfoPanelTitle"]], [
                                    "Info Title",
                                ]),
                                "\n                            ",
                                e("div", [["class", "heading bold medium"], ["id", "divInfoPanelDetail"]], [
                                    "Info Detail",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["style", "display: flex; justify-content: flex-end;"]], [
                                "\n                            ",
                                w(e("div", [["id", "nextButtonWelcomeScreen"], ["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "25"]], [
                                    "Next",
                                ]), "click", "nextInfoStep();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "quizScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        e("div", [["class", "roundex-box-middle"]], [
                            "\n                        ",
                            e("div", [["class", "safety_question_container"]], []),
                            "\n                        ",
                            e("div", [["class", "heading bold large"], ["id", "divSafetyQuizTitle"]], [
                                "Safety Quiz",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "heading bold medium"], ["id", "divSafetyQuizSubTitle"]], [
                                "Wallet",
                            ]),
                            "\n                        ",
                            e("div", [["class", "tab-name"], ["id", "divSafetyQuizQuestion"]], [
                                "\n                            What coins or tokens can you send to this wallet ?\n                        ",
                            ]),
                            "\n                        ",
                            e("label", [["class", "tab-label safety_quiz_label"], ["style", "text-align: left;display:none;cursor:pointer;"], ["id", "lblSafetyQuizChoice"]], [
                                "\n                            ",
                                e("input", [["type", "radio"], ["name", "quiz_option"], ["value", ""], ["class", "safety_quiz_option"], ["tabindex", "[TAB_INDEX]"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("form", [["id", "quizForm"], ["style", "display: flex; flex-direction: column; gap: 10px;"]], [
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "399"]], [
                                "\n                            Next\n                        ",
                            ]), "click", "submitQuizForm()"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "createWalletPasswordScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        e("div", [["class", "roundex-box-middle"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [["class", "heading large"], ["data-lang-key", "set-wallet-password"]], [
                                "Set Wallet Password",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "tab-name"], ["data-lang-key", "use-strong-password"]], [
                                "\n                            Use a strong and long password. And do not forget it!\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "password"]], [
                                    "Password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["style", "float: left; width: 80%;"]], [
                                        "\n                                    ",
                                        e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdPassword"], ["name", "password"], ["placeholder", "Enter a password"], ["data-placeholder-key", "enter-a-password"], ["tabindex", "1"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "float:left"]], [
                                        "\n                                    ",
                                        w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "2"]], []), "click", "togglePasswordBox(this, 'pwdPassword');"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "retype-password"]], [
                                    "Retype Password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["style", "float: left; width: 80%;"]], [
                                        "\n                                    ",
                                        e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdRetypePassword"], ["name", "password"], ["placeholder", "Retype the password"], ["data-placeholder-key", "retype-the-password"], ["tabindex", "3"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "float:left"]], [
                                        "\n                                    ",
                                        w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "4"]], []), "click", "togglePasswordBox(this, 'pwdRetypePassword');"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "5"]], [
                                "\n                            Next\n                        ",
                            ]), "click", "return checkNewPassword();"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "createWalletPromptScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "6"]], [
                            "\n\n                    ",
                        ]), "click", "backFromCreateOrRestoreWallet()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box"]], [
                            "\n                        ",
                            e("div", [["class", "safety_question_container"]], []),
                            "\n                        ",
                            e("div", [["class", "heading bold large"], ["data-lang-key", "create-restore-wallet"]], [
                                "Create or Restore Wallet",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "tab-name"], ["data-lang-key", "select-an-option"], ["tabindex", "1"]], [
                                "\n                            Select an option\n                        ",
                            ]),
                            "\n                        ",
                            e("form", [["id", "walletForm"], ["style", "display: flex; flex-direction: column; gap: 10px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left;cursor:pointer;"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "wallet_option"], ["value", "new_wallet"], ["class", "safety_quiz_option"], ["id", "optNewWallet"], ["tabindex", "2"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "create-new-wallet"], ["style", "cursor: pointer;"]], [
                                        "Create New Wallet",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optNewWallet').checked  = true;"),
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left; cursor: pointer;"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "wallet_option"], ["value", "wallet_from_seed"], ["class", "safety_quiz_option"], ["id", "optRestoreWalletFromSeed"], ["tabindex", "3"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "restore-wallet-from-seed"], ["style", "cursor: pointer;"]], [
                                        "Restore A Wallet From Seed Phrase",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optRestoreWalletFromSeed').checked = true;"),
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left; cursor: pointer;"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "wallet_option"], ["value", "restore_wallet_backup_file"], ["class", "safety_quiz_option"], ["id", "optRestoreWalletFromBackupFile"], ["tabindex", "4"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "restore-wallet-from-backup-file"], ["style", "cursor: pointer;"]], [
                                        "Restore A Wallet From a Backup File",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optRestoreWalletFromBackupFile').checked = true;"),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "5"]], [
                                "\n                            Next\n                        ",
                            ]), "click", "walletFormSubmitted()"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "walletTypeScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "6"]], [
                            "\n\n                    ",
                        ]), "click", "backFromWalletTypeScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box"]], [
                            "\n                        ",
                            e("div", [["class", "safety_question_container"]], []),
                            "\n                        ",
                            e("div", [["class", "heading bold large"], ["data-lang-key", "select-wallet-type"]], [
                                "Select Wallet Type",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "tab-name"], ["data-lang-key", "select-an-option"], ["tabindex", "1"]], [
                                "\n                            Select an option\n                        ",
                            ]),
                            "\n                        ",
                            e("form", [["id", "walletTypeForm"], ["style", "display: flex; flex-direction: column; gap: 10px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left; cursor: pointer;"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "wallet_type_option"], ["value", "default"], ["class", "safety_quiz_option"], ["id", "optWalletTypeDefault"], ["tabindex", "2"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "wallet-type-default"], ["style", "cursor: pointer;"]], [
                                        "Default",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optWalletTypeDefault').checked = true;"),
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left; cursor: pointer;"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "wallet_type_option"], ["value", "advanced"], ["class", "safety_quiz_option"], ["id", "optWalletTypeAdvanced"], ["tabindex", "3"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "wallet-type-advanced"], ["style", "cursor: pointer;"]], [
                                        "Advanced (20 times higher gas cost)",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optWalletTypeAdvanced').checked = true;"),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "4"]], [
                                "\n                            Next\n                        ",
                            ]), "click", "walletTypeFormSubmitted()"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n\n        ",
            e("div", [["class", "content"], ["id", "newSeedScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["style", "width:95%;"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "5"]], [
                            "\n\n                    ",
                        ]), "click", "backFromNewSeedScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box-middle"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [], [
                                "\n                            ",
                                e("div", [["class", "heading large"], ["style", "float:left;width:fit-content;"], ["data-lang-key", "seed-words"]], [
                                    "Seed Words",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["style", "width:100%;text-align:left;"], ["id", "divSeedHelp"]], [
                                "\n                            ",
                                e("ol", [], [
                                    "\n                                ",
                                    e("li", [["style", "margin-bottom:5px;"], ["data-lang-key", "seed-words-info-1"]], [
                                        "Ensure that no one is looking at the screen other than you.",
                                    ]),
                                    "\n                                ",
                                    e("li", [["style", "margin-bottom:5px;"], ["data-lang-key", "seed-words-info-2"]], [
                                        "Ensure that there is no camera pointed at this screen, including from your phone.",
                                    ]),
                                    "\n                                ",
                                    e("li", [["style", "margin-bottom:5px;"], ["data-lang-key", "seed-words-info-3"]], [
                                        "You should save the seed words safely offline and keep multiple copies in a trustworthy and safe location.",
                                    ]),
                                    "\n                                ",
                                    e("li", [["style", "margin-bottom:5px;"], ["data-lang-key", "seed-words-info-4"]], [
                                        "If these seed words are stolen or someone else gets access to them, your wallet is compromised.",
                                    ]),
                                    "\n                                ",
                                    e("li", [["style", "margin-bottom:5px;"]], [
                                        w(e("a", [["href", "#"], ["style", "color:black;text-decoration:underline;"], ["data-lang-key", "seed-words-show"], ["tabindex", "1"], ["id", "aRevealSeed"], ["autofocus", ""]], [
                                            "Click here to reveal the seed words.",
                                        ]), "click", "return showSeedPanel();"),
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container scrollbar seedwrapper"], ["style", "overflow:auto;display:none;"], ["id", "divSeedPanel"]], [
                                "\n                            ",
                                e("div", [["class", "tab-content mt-2"], ["style", "margin:auto;"]], [
                                    "\n                                ",
                                    e("div", [["class", "tab-pane fade active show"], ["id", "newSeedScreenPanel"], ["role", "tabpanel"]], [
                                        "\n                                    ",
                                        e("div", [["class", "divSeedTable"]], [
                                            "\n                                        ",
                                            e("div", [["class", "divSeedBody"], ["tabindex", "2"]], [
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead1"], ["id", "newSeedRowHead1"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"], ["id", "divNewSeed0"]], [
                                                            "HELLOWORLD",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"], ["id", "divNewSeed1"]], [
                                                            "AEROPLANE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"], ["id", "divNewSeed2"]], [
                                                            "ALRIGHT",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"], ["id", "divNewSeed3"]], [
                                                            "MOTIVATE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead2"], ["id", "newSeedRowHead2"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"], ["id", "divNewSeed4"]], [
                                                            "BICYCLE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"], ["id", "divNewSeed5"]], [
                                                            "LOOPWARE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"], ["id", "divNewSeed6"]], [
                                                            "DINGDONG",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"], ["id", "divNewSeed7"]], [
                                                            "PINGPONG",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead3"], ["id", "newSeedRowHead3"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"], ["id", "divNewSeed8"]], [
                                                            "PINTHAT",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"], ["id", "divNewSeed9"]], [
                                                            "POROTECH",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"], ["id", "divNewSeed10"]], [
                                                            "MYSPIRIN",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"], ["id", "divNewSeed11"]], [
                                                            "OKFINE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead4"], ["id", "newSeedRowHead4"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"], ["id", "divNewSeed12"]], [
                                                            "NAVY",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"], ["id", "divNewSeed13"]], [
                                                            "ME",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"], ["id", "divNewSeed14"]], [
                                                            "YES",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"], ["id", "divNewSeed15"]], [
                                                            "WITHER",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead5"], ["id", "newSeedRowHead5"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"], ["id", "divNewSeed16"]], [
                                                            "OK",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"], ["id", "divNewSeed17"]], [
                                                            "HIKE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"], ["id", "divNewSeed18"]], [
                                                            "HELPWIRE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"], ["id", "divNewSeed19"]], [
                                                            "CHOCOLATE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead6"], ["id", "newSeedRowHead6"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"], ["id", "divNewSeed20"]], [
                                                            "MILKSWEET",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"], ["id", "divNewSeed21"]], [
                                                            "PIZZA",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"], ["id", "divNewSeed22"]], [
                                                            "SUGAR",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"], ["id", "divNewSeed23"]], [
                                                            "HONEY",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead7"], ["id", "newSeedRowHead7"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"], ["id", "divNewSeed24"]], [
                                                            "PINEAPPLE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"], ["id", "divNewSeed25"]], [
                                                            "MANGO",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"], ["id", "divNewSeed26"]], [
                                                            "HOSTLY",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"], ["id", "divNewSeed27"]], [
                                                            "PINTBUG",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead8"], ["id", "newSeedRowHead8"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"], ["id", "divNewSeed28"]], [
                                                            "MICROWIN",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"], ["id", "divNewSeed29"]], [
                                                            "MEGABIG",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"], ["id", "divNewSeed30"]], [
                                                            "ALRIGHTY",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"], ["id", "divNewSeed31"]], [
                                                            "WHYNOT",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead9"], ["id", "newSeedRowHead9"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"], ["id", "divNewSeed32"]], [
                                                            "HELLOWORLD",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"], ["id", "divNewSeed33"]], [
                                                            "YOGHURT",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"], ["id", "divNewSeed34"]], [
                                                            "SAUCE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"], ["id", "divNewSeed35"]], [
                                                            "WHO",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead10"], ["id", "newSeedRowHead10"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"], ["id", "divNewSeed36"]], [
                                                            "WHOM",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"], ["id", "divNewSeed37"]], [
                                                            "HOW",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"], ["id", "divNewSeed38"]], [
                                                            "WHY",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"], ["id", "divNewSeed39"]], [
                                                            "TAKECARE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead11"], ["id", "newSeedRowHead11"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"], ["id", "divNewSeed40"]], [
                                                            "BLITLINE",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"], ["id", "divNewSeed41"]], [
                                                            "PIGHOPS",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"], ["id", "divNewSeed42"]], [
                                                            "BUNTMECA",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"], ["id", "divNewSeed43"]], [
                                                            "HASTILY",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead12"], ["id", "newSeedRowHead12"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"], ["id", "divNewSeed44"]], [
                                                            "PATIO",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"], ["id", "divNewSeed45"]], [
                                                            "LINTPICK",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"], ["id", "divNewSeed46"]], [
                                                            "NUTCRACK",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"], ["id", "divNewSeed47"]], [
                                                            "QWERTY",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                        ",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        c(" DivTable.com "),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n\n                        ",
                            e("div", [["id", "divNewSeedButtons"], ["style", "display:none;"]], [
                                "\n                            ",
                                w(e("div", [["class", "copy-container"], ["role", "button"], ["style", "float:left;"], ["tabindex", "3"]], []), "click", "copyNewSeed()"),
                                w(e("a", [["href", "#"], ["style", "float:left;margin-left:5px;"]], [
                                    "copy",
                                ]), "click", "copyNewSeed()"),
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["style", "float:right;"], ["id", "divNextSeed"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "4"]], [
                                    "\n                                Next\n                            ",
                                ]), "click", "showVerifySeedPanel()"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "seedVerifyScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["style", "width:95%;"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "50"]], [
                            "\n\n                    ",
                        ]), "click", "backToSeedScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box-middle"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [], [
                                "\n                            ",
                                e("div", [["class", "heading large"], ["style", "float:left;width:fit-content;"], ["data-lang-key", "verify-seed-words"]], [
                                    "Verify Seed Words",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container scrollbar seedwrapper"], ["style", "overflow:auto;"], ["id", "divSeedVerifyPanel"]], [
                                "\n                            ",
                                e("div", [["class", "tab-content mt-2"], ["style", "margin:auto;"]], [
                                    "\n                                ",
                                    e("div", [["class", "tab-pane fade active show"], ["id", "verifySeedScreenPanel"], ["role", "tabpanel"]], [
                                        "\n                                    ",
                                        e("div", [["class", "divSeedTable"]], [
                                            "\n                                        ",
                                            e("div", [["class", "divSeedBody"]], [
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead1"], ["id", "verifySeedRowHead1"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedA1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedA2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedA3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedA4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead2"], ["id", "verifySeedRowHead2"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedB1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedB2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedB3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedB4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead3"], ["id", "verifySeedRowHead3"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedC1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedC2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedC3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedC4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead4"], ["id", "verifySeedRowHead4"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedD1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedD2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedD3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedD4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead5"], ["id", "verifySeedRowHead5"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedE1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedE2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedE3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedE4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead6"], ["id", "verifySeedRowHead6"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedF1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedF2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedF3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedF4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead7"], ["id", "verifySeedRowHead7"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedG1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedG2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedG3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedG4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead8"], ["id", "verifySeedRowHead8"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedH1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedH2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedH3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedH4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead9"], ["id", "verifySeedRowHead9"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedI1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedI2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedI3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedI4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead10"], ["id", "verifySeedRowHead10"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedJ1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedJ2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedJ3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedJ4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead11"], ["id", "verifySeedRowHead11"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedK1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedK2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedK3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedK4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead12"], ["id", "verifySeedRowHead12"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedL1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedL2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedL3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtSeedL4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                        ",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["style", "float:right;"], ["id", "divVerifySeedButton"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "49"]], [
                                "\n                            Next\n                        ",
                            ]), "click", "verifySeedWords();"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "restoreSeedTypeScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "6"]], [
                            "\n\n                    ",
                        ]), "click", "backFromRestoreSeedTypeScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box"]], [
                            "\n                        ",
                            e("div", [["class", "safety_question_container"]], []),
                            "\n                        ",
                            e("div", [["class", "heading bold large"], ["data-lang-key", "select-seed-word-length"]], [
                                "How many seed words do you have?",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "tab-name"], ["data-lang-key", "select-an-option"], ["tabindex", "1"]], [
                                "\n                            Select an option\n                        ",
                            ]),
                            "\n                        ",
                            e("form", [["id", "restoreSeedTypeForm"], ["style", "display: flex; flex-direction: column; gap: 10px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left; cursor: pointer;"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "seed_length_option"], ["value", "32"], ["class", "safety_quiz_option"], ["id", "optSeedLength32"], ["tabindex", "2"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "seed-length-32"], ["style", "cursor: pointer;"]], [
                                        "32 words (A1 to H4)",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optSeedLength32').checked = true;"),
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left; cursor: pointer;"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "seed_length_option"], ["value", "36"], ["class", "safety_quiz_option"], ["id", "optSeedLength36"], ["tabindex", "3"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "seed-length-36"], ["style", "cursor: pointer;"]], [
                                        "36 words (A1 to I4)",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optSeedLength36').checked = true;"),
                                "\n                            ",
                                w(e("div", [["class", "tab-label"], ["style", "text-align: left; cursor: pointer;"]], [
                                    "\n                                ",
                                    e("input", [["type", "radio"], ["name", "seed_length_option"], ["value", "48"], ["class", "safety_quiz_option"], ["id", "optSeedLength48"], ["tabindex", "4"]], []),
                                    "\n                                ",
                                    e("label", [["data-lang-key", "seed-length-48"], ["style", "cursor: pointer;"]], [
                                        "48 words (A1 to L4)",
                                    ]),
                                    "\n                            ",
                                ]), "click", "document.getElementById('optSeedLength48').checked = true;"),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "5"]], [
                                "\n                            Next\n                        ",
                            ]), "click", "restoreSeedTypeFormSubmitted()"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "restoreSeedScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["style", "width:95%;"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "50"]], [
                            "\n\n                    ",
                        ]), "click", "backFromRestoreSeedScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box-middle"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [], [
                                "\n                            ",
                                e("div", [["class", "heading large"], ["style", "float:left;width:fit-content;"], ["data-lang-key", "restore-wallet-from-seed"]], [
                                    "Restore Wallet From Seed Words",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container scrollbar seedwrapper"], ["style", "overflow:auto;"], ["id", "divSeedRestorePanel"]], [
                                "\n                            ",
                                e("div", [["class", "tab-content mt-2"], ["style", "margin:auto;"]], [
                                    "\n                                ",
                                    e("div", [["class", "tab-pane fade active show"], ["id", "restoreSeedScreenPanel"], ["role", "tabpanel"]], [
                                        "\n                                    ",
                                        e("div", [["class", "divSeedTable"]], [
                                            "\n                                        ",
                                            e("div", [["class", "divSeedBody"]], [
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead1"], ["id", "restoreSeedRowHead1"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedA1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedA2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedA3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "A4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow1"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedA4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead2"], ["id", "restoreSeedRowHead2"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedB1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedB2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedB3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "B4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow2"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedB4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead3"], ["id", "restoreSeedRowHead3"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedC1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedC2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedC3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "C4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow3"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedC4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead4"], ["id", "restoreSeedRowHead4"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedD1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedD2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedD3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "D4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow4"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedD4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead5"], ["id", "restoreSeedRowHead5"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedE1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedE2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedE3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "E4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow5"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedE4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead6"], ["id", "restoreSeedRowHead6"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedF1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedF2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedF3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "F4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow6"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedF4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead7"], ["id", "restoreSeedRowHead7"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedG1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedG2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedG3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "G4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow7"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedG4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead8"], ["id", "restoreSeedRowHead8"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedH1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedH2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedH3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "H4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow8"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedH4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead9"], ["id", "restoreSeedRowHead9"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedI1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedI2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedI3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "I4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow9"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedI4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead10"], ["id", "restoreSeedRowHead10"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedJ1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedJ2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedJ3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "J4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow10"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedJ4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead11"], ["id", "restoreSeedRowHead11"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedK1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedK2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedK3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "K4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow11"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedK4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                            ",
                                                e("div", [["class", "seedrowhead12"], ["id", "restoreSeedRowHead12"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L1",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedL1"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L2",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedL2"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L3",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedL3"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedCell"]], [
                                                        "\n                                                    ",
                                                        e("div", [], [
                                                            "L4",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedrow12"]], [
                                                            e("div", [["class", "entrybox edit-div"], ["contenteditable", "true"], ["id", "txtRestoreSeedL4"]], []),
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                        ",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["style", "float:right;"], ["id", "divRestoreSeedButton"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "49"]], [
                                "\n                            Next\n                        ",
                            ]), "click", "restoreSeed();"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "restoreWalletScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "5"]], [
                            "\n\n                    ",
                        ]), "click", "backToCreateWalletPromptScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box"]], [
                            "\n                        ",
                            e("div", [["class", "heading bold large"], ["data-lang-key", "restore-wallet-from-backup"]], [
                                "Restore Wallet From Backup File",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["style", "float: left; width: fit-content;"]], [
                                "\n                            ",
                                e("input", [["type", "file"], ["class", "custom-file-input"], ["id", "filRestoreWallet"], ["tabindex", "1"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "text-align:left;font-size:12px;color:green;"], ["id", "divRestoreWalletFilename"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "enter-above-wallet-password"]], [
                                    "Enter the above wallet's password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["style", "float: left; width: 80%;"]], [
                                        "\n                                    ",
                                        e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdRestoreWallet"], ["name", "password"], ["data-placeholder-key", "password"], ["placeholder", "Enter the above wallet's password"], ["tabindex", "2"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "float:left"]], [
                                        "\n                                    ",
                                        w(e("img", [["src", "assets/svg/eye-outline.svg"], ["data-alt-key", "show-password"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["role", "button"], ["tabindex", "3"]], []), "click", "togglePasswordBox(this, 'pwdRestoreWallet');"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; justify-content: flex-end;"]], [
                                "\n                            ",
                                w(e("div", [["id", "nextButtonRestoreWalletScreen"], ["class", "large_button_container heading large"], ["data-lang-key", "open"], ["role", "button"], ["tabindex", "4"]], [
                                    "Open",
                                ]), "click", "restoreWalletFromFile();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "confirmWalletScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "50"]], [
                                "\n\n                        ",
                            ]), "click", "backFromConfirmWalletScreen()"),
                            "\n                        ",
                            e("div", [["class", "heading large"], ["data-lang-key", "confirm-wallet"]], [
                                "Confirm Wallet",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "tab-name"], ["style", "color:black;"], ["data-lang-key", "confirm-wallet-description"]], [
                                    "\n                                Check your wallet address. If this is not the correct address, you may press back to review and edit the seed words.\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["class", "tab-name"], ["style", "color:black;"], ["data-lang-key", "address"]], [
                                        "Address",
                                    ]),
                                    "\n                                ",
                                    e("div", [["id", "confirmWalletAddress"], ["class", "tab-name text-wallet-address"], ["style", "color: #000000; word-break: break-all;"]], [
                                        "\n\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; flex-direction: row; height: 40px; justify-content: center;"]], [
                                "\n                            ",
                                w(e("div", [["class", "copy-container"], ["role", "button"], ["tabindex", "1"]], [
                                    "\n\n                            ",
                                ]), "click", "return copyConfirmWalletAddress();"),
                                "\n                            ",
                                w(e("div", [["class", "scan-container"], ["role", "button"], ["style", "margin-left:15px;margin-top:-2px;"], ["tabindex", "2"]], [
                                    "\n\n                            ",
                                ]), "click", "return openBlockExplorerAccount();"),
                                "\n                            ",
                                e("div", [["style", "float: left; width: 30px; height: 30px; margin-left:15px; display: none;"], ["id", "divConfirmWalletLoadingBalance"]], [
                                    "\n                                ",
                                    e("img", [["src", "assets/icons/loading.gif"], ["style", "width:30px;height:30px"], ["alt", "Loading"]], []),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "balance-container"], ["style", "display: flex;flex-direction: row;height: 40px;justify-content: center;margin-top:15px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading bold"], ["style", "height: 30px;font-size: 20px;margin-top: -15px;color: #35980e;width:fit-content;"]], [
                                    "\n                                ",
                                    e("span", [["style", "color:black;"], ["data-lang-key", "balance"]], [
                                        "Balance",
                                    ]),
                                    " : ",
                                    e("span", [["style", "color:green;"], ["id", "spnConfirmWalletBalance"]], [
                                        "-",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"], ["style", "margin-top: -25px;"]], [
                                "\n\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; justify-content: flex-end;"]], [
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "3"]], [
                                    "Next",
                                ]), "click", "nextFromConfirmWalletScreen()"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "verifyWalletPasswordScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [["class", "heading large"], ["data-lang-key", "verify-wallet-password"]], [
                                "Verify wallet password",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "tab-name"], ["style", "color:black;"], ["data-lang-key", "verify-wallet-password-info"]], [
                                    "\n                                Retype your wallet password, to verify that you remember it. Upon verification, your wallet will be saved.\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["style", "float: left; width: 80%;"]], [
                                        "\n                                    ",
                                        e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdVerifyWalletPassword"], ["name", "password"], ["placeholder", "Enter wallet password"], ["data-placeholder-key", "password"], ["tabindex", "1"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "float:left"]], [
                                        "\n                                    ",
                                        w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["role", "button"], ["tabindex", "2"]], []), "click", "togglePasswordBox(this, 'pwdVerifyWalletPassword');"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "3"]], [
                                "\n                            Next\n                        ",
                            ]), "click", "verifyWalletPassword()"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "backupWalletScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        e("div", [["class", "roundex-box-middle scrollbar"]], [
                            "\n                        ",
                            e("div", [["class", "heading bold large"], ["data-lang-key", "backup-wallet"]], [
                                "Backup Wallet1",
                            ]),
                            "\n                        ",
                            e("div", [["class", "heading large"]], [
                                "\n                            ",
                                e("p", [["data-lang-key", "backup-wallet-info-1"]], [
                                    "For additional safety, please make sure that you keep backup copies in atleast three different devices offline.",
                                ]),
                                "\n                            ",
                                e("p", [["data-lang-key", "backup-wallet-info-2"]], [
                                    "And remember you need your wallet password to restore the backup!",
                                ]),
                                "\n                            ",
                                e("p", [], [
                                    w(e("a", [["href", "#"], ["data-lang-key", "backup-wallet-skip"], ["style", "color:black;cursor:pointer;"], ["tabindex", "3"]], [
                                        "Click here to skip this step.",
                                    ]), "click", "return setWalletAddressAndShowWalletScreen(currentWalletAddress);"),
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["style", "display: flex; justify-content: flex-end;"]], [
                                "\n                            ",
                                w(e("div", [["id", "backupButton"], ["class", "large_button_container heading large"], ["data-lang-key", "backup"], ["role", "button"], ["tabindex", "1"]], [
                                    "Backup",
                                ]), "click", "backupCurrentWallet()"),
                                "\n                            ",
                                w(e("div", [["id", "nextButtonBackupWalletScreen"], ["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["style", "display:none;"], ["tabindex", "2"]], [
                                    "Next",
                                ]), "click", "setWalletAddressAndShowWalletScreen(currentWalletAddress)"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n    ",
        ]),
        t("\n\n    "),
        e("div", [["class", "tabs-wallet-content"], ["id", "main-content"], ["style", "display: none;"]], [
            "\n        ",
            e("div", [["class", "content"], ["id", "divMainContent"]], [
                "\n            ",
                e("div", [["class", "center-content home-content"], ["id", "HomeScreen"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        e("div", [["class", "roundex-box boxeffect"]], [
                            "\n                        ",
                            e("div", [["class", "wallet-address-container"]], [
                                "\n                            ",
                                e("div", [["id", "walletAddress"], ["class", "tab-name text-wallet-address"], ["style", "color: #000000; "]], [
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; flex-direction: row; height: 40px; justify-content: center;"]], [
                                "\n                            ",
                                w(e("div", [["class", "copy-container"], ["role", "button"], ["tabindex", "1"]], [
                                    "\n\n                            ",
                                ]), "click", "return copyAddress();"),
                                "\n                            ",
                                w(e("div", [["class", "scan-container"], ["role", "button"], ["style", "margin-left:15px;margin-top:-2px;"], ["tabindex", "2"]], [
                                    "\n\n                            ",
                                ]), "click", "return openBlockExplorerAccount();"),
                                "\n                            ",
                                w(e("div", [["class", "refresh-container"], ["role", "button"], ["style", "margin-left:15px;"], ["id", "divRefreshBalance"], ["tabindex", "3"]], [
                                    "\n\n                            ",
                                ]), "click", "refreshAccountBalance();"),
                                "\n                            ",
                                e("div", [["style", "float: left; width: 30px; height: 30px; margin-left:15px;"], ["id", "divLoadingBalance"]], [
                                    "\n                                ",
                                    e("img", [["src", "assets/icons/loading.gif"], ["style", "width:30px;height:30px"]], []),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "balance-container"], ["style", "display: flex;flex-direction: row;height: 40px;justify-content: center;margin-top:15px;"]], [
                                "\n                            ",
                                e("div", [["id", "totalBalance"], ["class", "heading bold"], ["style", "height: 30px;font-size: 20px;margin-top: -15px;color: #35980e;width:fit-content;"]], [
                                    "\n                                ",
                                    e("span", [["style", "color:black;"], ["data-lang-key", "balance"]], [
                                        "Balance",
                                    ]),
                                    " : ",
                                    e("span", [["style", "color:green;"], ["id", "spnAccountBalance"]], []),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"], ["style", "margin-top: -25px;"]], [
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "buttons-container"]], [
                                "\n                            ",
                                w(e("div", [["class", "buttonBox"], ["role", "button"], ["tabindex", "3"]], [
                                    "\n                                ",
                                    e("div", [["class", "button"], ["style", "background: #FFB400 !important; border-radius: 10px; align-self: center; min-height: 50px; min-width: 50px; "]], [
                                        "\n                                    ",
                                        e("img", [["src", "assets/svg/arrow-up-outline.svg"], ["alt", "Send"], ["style", "width: 30px; height: 30px; position: relative; top: 50%; transform: translateY(-50%);"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "button-name"], ["data-lang-key", "send"]], [
                                        "Send",
                                    ]),
                                    "\n                            ",
                                ]), "click", "showSendScreen();"),
                                "\n                            ",
                                w(e("div", [["class", "buttonBox"], ["role", "button"], ["tabindex", "4"]], [
                                    "\n                                ",
                                    e("div", [["class", "button"], ["style", "background: #1DCC70 !important; border-radius: 10px; align-self: center; min-height: 50px; min-width: 50px; "]], [
                                        "\n                                    ",
                                        e("img", [["src", "assets/svg/arrow-down-outline.svg"], ["alt", "Receive"], ["style", "width: 30px; height: 30px; position: relative; top: 50%; transform: translateY(-50%);"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "button-name"], ["data-lang-key", "receive"], ["role", "button"]], [
                                        "Receive",
                                    ]),
                                    "\n                            ",
                                ]), "click", "showReceiveScreen();"),
                                "\n                            ",
                                w(e("div", [["class", "buttonBox"], ["role", "button"], ["tabindex", "5"]], [
                                    "\n                                ",
                                    e("div", [["class", "button"], ["style", "background: #55D0F0 !important; border-radius: 10px; align-self: center; min-height: 50px; min-width: 50px; "]], [
                                        "\n                                    ",
                                        e("img", [["src", "assets/svg/txn-outline.svg"], ["alt", "Transactions"], ["style", "width: 30px; height: 30px; position: relative; top: 50%; transform: translateY(-50%);"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "button-name"], ["data-lang-key", "transactions"]], [
                                        "Transactions",
                                    ]),
                                    "\n                            ",
                                ]), "click", "showTransactionsScreen();"),
                                "\n                            ",
                                w(e("div", [["class", "buttonBox"], ["role", "button"], ["tabindex", "6"]], [
                                    "\n                                ",
                                    e("div", [["class", "button button-swap"], ["style", "border-radius: 10px; align-self: center; min-height: 50px; min-width: 50px; "]], [
                                        "\n                                    ",
                                        e("img", [["src", "assets/svg/dex-swap-outline.svg"], ["alt", "Swap"], ["style", "width: 30px; height: 30px; position: relative; top: 50%; transform: translateY(-50%);"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "button-name"], ["data-lang-key", "swap"]], [
                                        "Swap",
                                    ]),
                                    "\n                            ",
                                ]), "click", "showSwapScreen();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["id", "divAccountTokens"], ["style", "display: none"]], [
                        "\n                    ",
                        e("div", [["id", "divTokenTabs"], ["style", "display:none; text-align:center; margin-bottom:8px;"]], [
                            "\n                        ",
                            w(e("button", [["type", "button"], ["id", "btnTokensRecognized"], ["data-lang-key", "tokens-tab"], ["style", "cursor:pointer; border:none; background:none; padding:6px 12px; font-weight:700; border-bottom:2px solid green;"]], [
                                "Tokens",
                            ]), "click", "return selectTokenTab(false);"),
                            "\n                        ",
                            w(e("button", [["type", "button"], ["id", "btnTokensUnrecognized"], ["data-lang-key", "unrecognized-tokens-tab"], ["style", "cursor:pointer; border:none; background:none; padding:6px 12px; font-weight:400; border-bottom:2px solid transparent;"]], [
                                "Unrecognized Tokens",
                            ]), "click", "return selectTokenTab(true);"),
                            "\n                    ",
                        ]),
                        "\n                    ",
                        e("div", [["class", "roundex-box-small boxeffect scrollbar"], ["id", "divMainScreenTokens"], ["style", "overflow-y: auto;overflow-x: auto;max-height: 295px;text-align: left;"]], [
                            "\n                        ",
                            e("table", [["class", "styled-table"]], [
                                "\n                            ",
                                e("thead", [], [
                                    "\n                            ",
                                    e("tr", [], [
                                        "\n                                ",
                                        e("th", [["data-lang-key", "symbol"]], [
                                            "Symbol",
                                        ]),
                                        "\n                                ",
                                        e("th", [["data-lang-key", "balance"]], [
                                            "Balance",
                                        ]),
                                        "\n                                ",
                                        e("th", [["data-lang-key", "contract"]], [
                                            "Contract",
                                        ]),
                                        "\n                                ",
                                        e("th", [["data-lang-key", "name"]], [
                                            "Name",
                                        ]),
                                        "\n                            ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("tbody", [["id", "tbodyAccountTokens"]], [
                                    "\n                            ",
                                    e("tr", [["class", "token-list-row"]], [
                                        "\n                                ",
                                        e("td", [], [
                                            "[TOKEN_SYMBOL]",
                                        ]),
                                        "\n                                ",
                                        e("td", [], [
                                            "[TOKEN_BALANCE]",
                                        ]),
                                        "\n                                ",
                                        e("td", [], [
                                            w(e("a", [["href", "#"]], [
                                                "[SHORT_CONTRACT]",
                                            ]), "click", "return OpenScanAddress('[TOKEN_CONTRACT]');"),
                                        ]),
                                        "\n                                ",
                                        e("td", [], [
                                            "[TOKEN_NAME]",
                                        ]),
                                        "\n                            ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n\n            ",
                e("div", [["class", "center-content home-content"], ["id", "SendScreen"], ["style", "margin-top:110px;"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "300"]], [
                            "\n\n                    ",
                        ]), "click", "showWalletScreen();"),
                        "\n                    ",
                        e("div", [["id", "divSendScreenInner"], ["class", "roundex-box scrollbar"], ["style", "padding-top: 15px; padding-bottom: 15px;overflow-y: auto;overflow-x: auto;"]], [
                            "\n                        ",
                            e("div", [["class", "gas-header-row"]], [
                                "\n                            ",
                                e("div", [["class", "heading bold"], ["data-lang-key", "send"]], [
                                    "Send",
                                ]),
                                "\n                            ",
                                e("div", [["class", "gas-header-right"]], [
                                    "\n                                ",
                                    e("span", [["id", "spanSendGasFee"], ["class", "gas-fee-label"]], []),
                                    "\n                                ",
                                    w(e("div", [["id", "divSendGasIcon"], ["class", "gas-container"], ["role", "button"], ["tabindex", "301"]], []), "click", "return onSendGasIconClick();"),
                                    "\n                            ",
                                ]),
                                "                                                    \n                        ",
                            ]),
                            "                        \n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["id", "divTokenList"]], [
                                "\n                            ",
                                e("div", [["id", "divSendShowUnrecognized"], ["style", "display:none; text-align:left; margin-bottom:8px;"]], [
                                    "\n                                ",
                                    w(e("input", [["type", "checkbox"], ["id", "chkSendShowUnrecognized"], ["tabindex", "302"]], []), "change", "onToggleSendUnrecognized();"),
                                    "\n                                ",
                                    w(e("label", [["for", "chkSendShowUnrecognized"], ["tabindex", "0"], ["data-lang-key", "show-unrecognized-tokens"], ["style", "cursor: pointer; color:black;"]], [
                                        "Show unrecognized tokens",
                                    ]), "keydown", "if(event.key==='Enter'||event.key===' '){event.preventDefault(); document.getElementById('chkSendShowUnrecognized').click();}"),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "selectwrapper"]], [
                                    "\n                                ",
                                    w(e("select", [["id", "ddlCoinTokenToSend"], ["class", "selectbox"], ["tabindex", "303"]], [
                                        "\n                                    ",
                                        e("option", [["value", "Q"]], [
                                            "Q",
                                        ]),
                                        "\n                                    ",
                                        e("option", [["value", "Y2Q"]], [
                                            "Y2Q",
                                        ]),
                                        "\n                                    ",
                                        e("option", [["value", "hei"]], [
                                            "Heisen",
                                        ]),
                                        "\n                                ",
                                    ]), "change", "updateInfoSendScreen();"),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 400;color:black;"], ["autocomplete", "off"], ["id", "txtTokenContractAddress"], ["name", "contract_address"], ["data-placeholder-key", "token-contract-address"], ["placeholder", "token contract address"], ["tabindex", "304"]], []),
                                "\n\n                            ",
                                e("div", [["id", "divCoinTokenToSend"], ["style", "font-size: small"]], [
                                    "0x0000000000000000000000000000000000000000000000000000000000001000",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["id", "divSendScreenBalanceBox"]], [
                                "\n                            ",
                                e("div", [["class", "tab-name text-wallet-address"], ["style", "text-align: left; font-weight: 200"], ["data-lang-key", "balance"]], [
                                    "Balance",
                                ]),
                                "\n                            ",
                                e("div", [["class", "heading bold"], ["style", "text-align: left; font-size: 20px; color:green;"], ["id", "divBalanceSendScreen"]], []),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "address-to-send"]], [
                                    "Address to send to",
                                ]),
                                "\n                            ",
                                e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 400;color:black;"], ["autocomplete", "off"], ["id", "txtSendAddress"], ["name", "send_address"], ["data-placeholder-key", "address-to-send"], ["placeholder", "Address to send to"], ["tabindex", "305"]], []),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "quantity-to-send"]], [
                                    "Quantity to send",
                                ]),
                                "\n                            ",
                                e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "number"], ["autocomplete", "off"], ["id", "txtSendQuantity"], ["name", "send_quantity"], ["data-placeholder-key", "quantity-to-send"], ["placeholder", "Quantity to send"], ["tabindex", "306"]], []),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["id", "divCurrentNonce"]], [
                                "\n                            ",
                                e("div", [["data-lang-key", "nonce-help"], ["style", "text-align: left;"]], []),
                                "\n                            ",
                                e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "number"], ["autocomplete", "off"], ["id", "txtCurrentNonce"], ["name", "current_nonce"], ["data-placeholder-key", "current-nonce"], ["placeholder", "Current Nonce"], ["tabindex", "307"], ["maxlength", "6"]], []),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["style", "float: left; width: 80%;"]], [
                                        "\n                                    ",
                                        e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdSend"], ["name", "password"], ["data-placeholder-key", "password"], ["placeholder", "Enter the password"], ["tabindex", "308"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "float:left"]], [
                                        "\n                                    ",
                                        w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "309"]], []), "click", "togglePasswordBox(this, 'pwdSend');"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; justify-content: flex-end;"]], [
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "send"], ["role", "button"], ["tabindex", "310"], ["id", "btnSendCoins"]], [
                                    "\n                                Send\n                            ",
                                ]), "click", "return sendCoins();"),
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "sign-offline"], ["role", "button"], ["tabindex", "311"], ["style", "margin-left:15px;"], ["id", "btnOfflineSign"]], [
                                    "\n                                Offline Sign\n                            ",
                                ]), "click", "return signOfflineSend();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n\n            ",
                e("div", [["class", "center-content home-content"], ["id", "OfflineSignScreen"], ["style", "margin-top:110px;"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "3000"]], [
                            "\n\n                    ",
                        ]), "click", "showSendScreen();"),
                        "\n                    ",
                        e("div", [["class", "tab-name"], ["style", "color:black;"]], [
                            "\n                        ",
                            e("p", [], [
                                "\n                            ",
                                e("label", [["data-lang-key", "offline-txn-help"]], [
                                    "Copy the below signed transaction and submit it at: ",
                                ]),
                                " ",
                                w(e("a", [["href", "#"]], [
                                    "https://QuantumCoin.org/offline-transaction-signing.html",
                                ]), "click", "return openOfflineTxnSigningUrl();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                    ",
                        e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [["class", "heading bold"], ["data-lang-key", "signed-transaction-details"]], [
                                "Signed Transaction Details",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("textarea", [["id", "txtSignedSendTransaction"], ["style", "width: 100%;"], ["disabled", ""], ["rows", "15"], ["cols", "100"], ["tabindex", "1"]], [
                                    "\n                             ",
                                ]),
                                "\n                            ",
                                w(e("div", [["class", "copy-container"], ["role", "button"], ["style", "float:left;"], ["id", "divCopySignedSendTransaction"], ["tabindex", "2"]], []), "click", "copySignedSendTransaction()"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n\n            ",
                e("div", [["class", "center-content home-content"], ["id", "SwapScreen"], ["style", "margin-top:110px;"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["style", "width:93%;"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "320"], ["id", "divBackSwapScreen"]], []), "click", "onSwapScreenBackClick();"),
                        "\n                    ",
                        e("div", [["id", "divSwapScreenInner"], ["class", "roundex-box scrollbar"], ["style", "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto;max-height:590px;"]], [
                            "\n                        ",
                            e("div", [["class", "gas-header-row"]], [
                                "\n                            ",
                                e("div", [["class", "heading bold"], ["data-lang-key", "swap"]], [
                                    "Swap",
                                ]),
                                "\n                            ",
                                e("div", [["class", "gas-header-right"]], [
                                    "\n                                ",
                                    e("span", [["id", "spanSwapGasFee"], ["class", "gas-fee-label"]], []),
                                    "\n                                ",
                                    w(e("div", [["id", "divSwapGasIcon"], ["class", "gas-container"], ["role", "button"], ["tabindex", "343"]], []), "click", "return onSwapGasIconClick();"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "gap:2px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "swap-from-token"], ["style", "margin-top: 3px;"]], [
                                    "From token",
                                ]),
                                "\n                            ",
                                e("div", [["class", "selectwrapper"]], [
                                    "\n                                ",
                                    w(e("select", [["id", "ddlSwapFromToken"], ["class", "selectbox"], ["tabindex", "321"]], []), "change", "updateSwapScreenInfo();"),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "input_container"], ["style", "margin-top:3px;gap:2px;"]], [
                                    "\n                                ",
                                    e("div", [["style", "font-size: 0.85em; color: #372339;"]], [
                                        "\n                                    ",
                                        e("span", [["data-lang-key", "balance"]], [
                                            "Balance",
                                        ]),
                                        ": ",
                                        w(e("span", [["id", "spanSwapFromBalance"], ["role", "button"], ["tabindex", "322"], ["class", "swap-balance-label"], ["style", "cursor:pointer;text-decoration:underline;"]], [
                                            "0",
                                        ]), "click", "return setSwapFromQuantityToBalance();"),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["id", "divSwapFromAllowanceRow"], ["style", "display: none; font-size: 0.85em; color: #372339; margin-top:4px;"]], [
                                        "\n                                    ",
                                        e("span", [["data-lang-key", "allowance"]], [
                                            "Allowance",
                                        ]),
                                        ": ",
                                        e("span", [["id", "spanSwapFromAllowance"]], [
                                            "0",
                                        ]),
                                        "\n                                    ",
                                        w(e("a", [["href", "#"], ["id", "aSwapRemoveAllowance"], ["data-lang-key", "remove-allowance"], ["style", "margin-left:8px;color:#0066cc;cursor:pointer;text-decoration:underline;"]], [
                                            "Remove allowance",
                                        ]), "click", "return onRemoveSwapAllowanceClick();"),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["id", "divSwapFromContractRow"], ["style", "font-size: 0.85em; color: #372339; margin-top:4px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 6px;"]], [
                                        "\n                                    ",
                                        w(e("a", [["href", "#"], ["id", "aSwapFromContract"], ["tabindex", "323"], ["style", "color: inherit; text-decoration: underline; word-break: break-all;"]], [
                                            "...",
                                        ]), "click", "openSwapFromContractInExplorer(); return false;"),
                                        "\n                                    ",
                                        w(e("span", [["class", "copy-container copy-container-small"], ["role", "button"], ["style", "flex-shrink: 0; width:15px; height:15px; cursor:pointer;"], ["tabindex", "324"], ["id", "divCopySwapFromContract"], ["title", "Copy"]], []), "click", "copySwapFromContractAddress();"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                w(e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "number"], ["autocomplete", "off"], ["id", "txtSwapFromQuantity"], ["name", "swap_from_quantity"], ["data-placeholder-key", "quantity"], ["placeholder", "Quantity"], ["tabindex", "325"], ["min", "0"], ["step", "any"]], []), "input", "debouncedUpdateToQuantityFromFrom();"),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "gap:2px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "swap-to-token"], ["style", "margin-top: 3px;"]], [
                                    "To token",
                                ]),
                                "\n                            ",
                                e("div", [["class", "selectwrapper"]], [
                                    "\n                                ",
                                    w(e("select", [["id", "ddlSwapToToken"], ["class", "selectbox"], ["tabindex", "326"]], []), "change", "updateSwapScreenInfo();"),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "input_container"], ["style", "margin-top:3px;gap:2px;"]], [
                                    "\n                                ",
                                    e("div", [["style", "font-size: 0.85em; color: #372339;"]], [
                                        "\n                                    ",
                                        e("span", [["data-lang-key", "balance"]], [
                                            "Balance",
                                        ]),
                                        ": ",
                                        w(e("span", [["id", "spanSwapToBalance"], ["role", "button"], ["tabindex", "327"], ["class", "swap-balance-label"], ["style", "cursor:pointer;text-decoration:underline;"]], [
                                            "0",
                                        ]), "click", "return setSwapToQuantityToBalance();"),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["id", "divSwapToContractRow"], ["style", "font-size: 0.85em; color: #372339; margin-top:4px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 6px;"]], [
                                        "\n                                    ",
                                        w(e("a", [["href", "#"], ["id", "aSwapToContract"], ["tabindex", "328"], ["style", "color: inherit; text-decoration: underline; word-break: break-all;"]], [
                                            "...",
                                        ]), "click", "openSwapToContractInExplorer(); return false;"),
                                        "\n                                    ",
                                        w(e("span", [["class", "copy-container copy-container-small"], ["role", "button"], ["style", "flex-shrink: 0; width:15px; height:15px; cursor:pointer;"], ["tabindex", "329"], ["id", "divCopySwapToContract"], ["title", "Copy"]], []), "click", "copySwapToContractAddress();"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                w(e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "number"], ["autocomplete", "off"], ["id", "txtSwapToQuantity"], ["name", "swap_to_quantity"], ["data-placeholder-key", "quantity"], ["placeholder", "Quantity"], ["tabindex", "330"], ["min", "0"], ["step", "any"]], []), "input", "debouncedUpdateFromQuantityFromTo();"),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; align-items: center; justify-content: flex-end; gap: 10px;margin-top:10px;"]], [
                                "\n                            ",
                                e("div", [["id", "divSwapQuoteLoading"], ["style", "display: none;"]], [
                                    "\n                                ",
                                    e("img", [["src", "assets/icons/loading.gif"], ["alt", "Loading"], ["style", "width:30px; height:30px;"]], []),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "next"], ["role", "button"], ["tabindex", "331"], ["id", "btnSwapNext"]], [
                                    "\n                                Next\n                            ",
                                ]), "click", "return onSwapNextClick();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                    ",
                        e("div", [["id", "divSwapConfirmPanel"], ["class", "roundex-box scrollbar"], ["style", "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto; max-height:590px; display: none;"]], [
                            "\n                        ",
                            e("div", [["class", "gas-header-row"]], [
                                "\n                            ",
                                e("div", [["class", "heading bold"], ["data-lang-key", "swap"]], [
                                    "Swap",
                                ]),
                                "\n                            ",
                                e("div", [["class", "gas-header-right"]], [
                                    "\n                                ",
                                    e("span", [["id", "spanSwapConfirmGasFee"], ["class", "gas-fee-label"]], []),
                                    "\n                                ",
                                    w(e("div", [["id", "divSwapConfirmGasIcon"], ["class", "gas-container"], ["role", "button"], ["tabindex", "344"]], []), "click", "return onSwapConfirmGasIconClick();"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["id", "divSwapConfirmLoading"], ["style", "display: none; margin-top: 8px; margin-bottom: 8px;"]], [
                                "\n                            ",
                                e("img", [["src", "assets/icons/loading.gif"], ["alt", "Loading"], ["style", "width:30px; height:30px;"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["id", "divSwapSlippageRow"], ["class", "input_container"], ["style", "margin-top: 8px; display: none;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "slippage"]], [
                                    "Slippage",
                                ]),
                                "\n                            ",
                                e("div", [["style", "display: flex; align-items: center; gap: 8px;"]], [
                                    "\n                                ",
                                    e("input", [["class", "tab-name"], ["type", "number"], ["id", "txtSwapSlippage"], ["min", "0"], ["max", "100"], ["step", "0.1"], ["value", "1"], ["style", "text-align: left; width: 60px; border: 1px solid #ccc; border-radius: 6px; padding: 6px;"], ["tabindex", "333"]], []),
                                    "\n                                ",
                                    e("span", [], [
                                        "%",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["id", "divSwapConfirmApprovalTxError"], ["style", "display: none; margin-top: 8px; color: #c00; font-size: 0.9em;"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 10px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "enter-wallet-password"]], [
                                    "Enter Wallet Password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "display:flex; align-items:center; gap:8px;"]], [
                                    "\n                                ",
                                    e("input", [["type", "password"], ["id", "pwdSwapConfirm"], ["autocomplete", "off"], ["placeholder", "Quantum Wallet Password"], ["data-placeholder-key", "password"], ["style", "text-align: left; width: 200px; border: 1px solid #ccc; border-radius: 6px; padding: 6px;"], ["tabindex", "337"]], []),
                                    "\n                                ",
                                    w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "338"]], []), "click", "togglePasswordBox(this, 'pwdSwapConfirm');"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; align-items: center; justify-content: flex-end; gap: 10px; margin-top: 20px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["role", "button"], ["tabindex", "339"], ["id", "btnSwapConfirmNext"]], [
                                    "\n                                Next\n                            ",
                                ]), "click", "return onSwapConfirmNextClick();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                    ",
                        e("div", [["id", "divSwapRemoveAllowancePanel"], ["class", "roundex-box scrollbar"], ["style", "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto; max-height:590px; display: none;"]], [
                            "\n                        ",
                            e("div", [["class", "gas-header-row"]], [
                                "\n                            ",
                                e("div", [["class", "heading bold"], ["data-lang-key", "remove-allowance-title"]], [
                                    "Remove allowance",
                                ]),
                                "\n                            ",
                                e("div", [["class", "gas-header-right"]], [
                                    "\n                                ",
                                    e("span", [["id", "spanRemoveAllowanceGasFee"], ["class", "gas-fee-label"]], []),
                                    "\n                                ",
                                    w(e("div", [["id", "divRemoveAllowanceGasIcon"], ["class", "gas-container"], ["role", "button"], ["tabindex", "345"]], []), "click", "return onRemoveAllowanceGasIconClick();"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 8px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "contract"]], [
                                    "Contract",
                                ]),
                                "\n                            ",
                                w(e("a", [["href", "#"], ["id", "aRemoveAllowanceContract"], ["style", "font-size: 0.9em; color: #0066cc; word-break: break-all; text-decoration: underline;"]], [
                                    "...",
                                ]), "click", "openRemoveAllowanceContractInExplorer(); return false;"),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["id", "divRemoveAllowanceError"], ["style", "display: none; margin-top: 8px; color: #c00; font-size: 0.9em;"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 10px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "enter-wallet-password"]], [
                                    "Enter Wallet Password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "display:flex; align-items:center; gap:8px;"]], [
                                    "\n                                ",
                                    e("input", [["type", "password"], ["id", "pwdRemoveAllowance"], ["autocomplete", "off"], ["placeholder", "Quantum Wallet Password"], ["data-placeholder-key", "password"], ["style", "text-align: left; width: 200px; border: 1px solid #ccc; border-radius: 6px; padding: 6px;"], ["tabindex", "338"]], []),
                                    "\n                                ",
                                    w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "339"]], []), "click", "togglePasswordBox(this, 'pwdRemoveAllowance');"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; align-items: center; justify-content: flex-end; gap: 10px; margin-top: 20px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["role", "button"], ["tabindex", "340"], ["id", "btnRemoveAllowanceRemove"]], [
                                    "\n                                ",
                                    e("span", [["data-lang-key", "remove"]], [
                                        "Remove",
                                    ]),
                                    "\n                            ",
                                ]), "click", "return onRemoveAllowanceRemoveClick();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                    ",
                        e("div", [["id", "divSwapAddAllowancePanel"], ["class", "roundex-box scrollbar"], ["style", "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto; max-height:590px; display: none;"]], [
                            "\n                        ",
                            e("div", [["class", "gas-header-row"]], [
                                "\n                            ",
                                e("div", [["class", "heading bold"], ["data-lang-key", "add-allowance-title"]], [
                                    "Add allowance",
                                ]),
                                "\n                            ",
                                e("div", [["class", "gas-header-right"]], [
                                    "\n                                ",
                                    e("span", [["id", "spanAddAllowanceGasFee"], ["class", "gas-fee-label"]], []),
                                    "\n                                ",
                                    w(e("div", [["id", "divAddAllowanceGasIcon"], ["class", "gas-container"], ["role", "button"], ["tabindex", "346"]], []), "click", "return onAddAllowanceGasIconClick();"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 8px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "contract"]], [
                                    "Contract",
                                ]),
                                "\n                            ",
                                w(e("a", [["href", "#"], ["id", "aAddAllowanceContract"], ["style", "font-size: 0.9em; color: #0066cc; word-break: break-all; text-decoration: underline;"]], [
                                    "...",
                                ]), "click", "openAddAllowanceContractInExplorer(); return false;"),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["id", "divAddAllowanceQuantityRow"], ["class", "input_container"], ["style", "margin-top: 8px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "approval-quantity"]], [
                                    "Approval Quantity",
                                ]),
                                "\n                            ",
                                e("div", [["style", "display: flex; align-items: center; gap: 8px;"]], [
                                    "\n                                ",
                                    w(e("input", [["class", "tab-name"], ["type", "number"], ["id", "txtAddAllowanceQuantity"], ["min", "0"], ["step", "any"], ["style", "text-align: left; width: 200px; border: 1px solid #ccc; border-radius: 6px; padding: 6px;"]], []), "input", "onAddAllowanceQuantityInput();"),
                                    "\n                                ",
                                    w(e("a", [["href", "#"], ["data-lang-key", "max"], ["style", "color: #0066cc; cursor: pointer;"]], [
                                        "Max",
                                    ]), "click", "return setAddAllowanceQuantityToMax();"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["id", "divAddAllowanceError"], ["style", "display: none; margin-top: 8px; color: #c00; font-size: 0.9em;"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 10px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "enter-wallet-password"]], [
                                    "Enter Wallet Password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "display:flex; align-items:center; gap:8px;"]], [
                                    "\n                                ",
                                    e("input", [["type", "password"], ["id", "pwdAddAllowance"], ["autocomplete", "off"], ["placeholder", "Quantum Wallet Password"], ["data-placeholder-key", "password"], ["style", "text-align: left; width: 200px; border: 1px solid #ccc; border-radius: 6px; padding: 6px;"], ["tabindex", "339"]], []),
                                    "\n                                ",
                                    w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "340"]], []), "click", "togglePasswordBox(this, 'pwdAddAllowance');"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; align-items: center; justify-content: flex-end; gap: 10px; margin-top: 20px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["role", "button"], ["tabindex", "341"], ["id", "btnAddAllowanceAdd"]], [
                                    "\n                                ",
                                    e("span", [["data-lang-key", "add"]], [
                                        "Add",
                                    ]),
                                    "\n                            ",
                                ]), "click", "return onAddAllowanceAddClick();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                    ",
                        e("div", [["id", "divSwapSuccessPanel"], ["class", "roundex-box scrollbar"], ["style", "padding-top: 15px; padding-bottom: 15px; overflow-y: auto; overflow-x: auto; max-height:590px; display: none;"]], [
                            "\n                        ",
                            e("div", [["class", "heading bold"], ["data-lang-key", "swap-succeeded"], ["style", "color: green;"]], [
                                "Swap transaction succeeded.",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 8px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "swap-from-token"]], [
                                    "From token",
                                ]),
                                "\n                            ",
                                e("span", [["id", "spanSwapSuccessFromTokenDisplay"], ["style", "font-size: 0.9em;"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 8px;"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "swap-to-token"]], [
                                    "To token",
                                ]),
                                "\n                            ",
                                e("span", [["id", "spanSwapSuccessToTokenDisplay"], ["style", "font-size: 0.9em;"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 12px;"]], [
                                "\n                            ",
                                e("table", [["class", "styled-table"], ["style", "width: 100%;"]], [
                                    "\n                                ",
                                    e("thead", [], [
                                        "\n                                    ",
                                        e("tr", [], [
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "token"]], [
                                                "Token",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "before"]], [
                                                "Before",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "after"]], [
                                                "After",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("tbody", [], [
                                        "\n                                    ",
                                        e("tr", [], [
                                            "\n                                        ",
                                            e("td", [["id", "tdSwapSuccessFromName"]], []),
                                            "\n                                        ",
                                            e("td", [["id", "tdSwapSuccessFromBefore"]], []),
                                            "\n                                        ",
                                            e("td", [["id", "tdSwapSuccessFromAfter"]], []),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        e("tr", [], [
                                            "\n                                        ",
                                            e("td", [["id", "tdSwapSuccessToName"]], []),
                                            "\n                                        ",
                                            e("td", [["id", "tdSwapSuccessToBefore"]], []),
                                            "\n                                        ",
                                            e("td", [["id", "tdSwapSuccessToAfter"]], []),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["style", "margin-top: 12px;"]], [
                                "\n                            ",
                                e("span", [["class", "heading medium"], ["data-lang-key", "gas-fee-spent"]], [
                                    "Gas fee spent (coins)",
                                ]),
                                "\n                            ",
                                e("span", [["id", "spanSwapSuccessGasFee"]], [
                                    "0",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; justify-content: flex-end; margin-top: 20px;"]], [
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["role", "button"], ["tabindex", "342"], ["id", "btnSwapSuccessOk"], ["style", "margin-left: auto;"]], [
                                    "\n                                ",
                                    e("span", [["data-lang-key", "ok"]], [
                                        "OK",
                                    ]),
                                    "\n                            ",
                                ]), "click", "return onSwapSuccessOkClick();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n\n            ",
                e("div", [["class", "center-content home-content"], ["id", "ReceiveScreen"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["style", "margin-top:110px;"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "310"], ["id", "divBackReceiveScreen"]], [
                            "\n\n                    ",
                        ]), "click", "showWalletScreen();"),
                        "\n                    ",
                        e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;overflow-y: auto;overflow-x: auto;"]], [
                            "\n                        ",
                            e("div", [["class", "heading bold"], ["data-lang-key", "receive-coins"]], [
                                "Receive Coins",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["style", "color:red"], ["data-lang-key", "send-only"]], [
                                "Send only DP coins to this address!",
                            ]),
                            "\n                        ",
                            e("div", [["id", "receiveWalletAddress"], ["class", "tab-name text-wallet-address"], ["style", "text-align: center; font-size: 0.88em;color:black;"]], [
                                "\n                        ",
                            ]),
                            "\n                        ",
                            w(e("div", [["class", "copy-container"], ["role", "button"], ["style", "display: flex; align-self: center;margin-bottom:10px;"], ["tabindex", "311"], ["id", "divCopyReceiveScreen"]], [
                                "\n\n                        ",
                            ]), "click", "return copyAddressReceiveScreen();"),
                            "\n                        ",
                            e("div", [["style", "text-align: center; max-height: 270px; display: flex; align-items: center; justify-content: center;"]], [
                                "\n                            ",
                                e("div", [["id", "qrcode"]], [
                                    "\n\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n\n            ",
                e("div", [["class", "center-content home-content"], ["id", "TransactionsScreen"], ["style", "margin-top:110px;"]], [
                    "\n\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["style", "width:95%;max-width: 95%;"]], [
                        "\n                    ",
                        e("div", [["style", "display: flex; margin-bottom: 5px;"]], [
                            "\n                        ",
                            w(e("div", [["class", "back-container"], ["role", "button"], ["style", "float: left;"], ["tabindex", "320"]], [
                                "\n\n                        ",
                            ]), "click", "showWalletScreen();"),
                            "\n                        ",
                            w(e("div", [["class", "refresh-container"], ["role", "button"], ["id", "divTxnRefreshStatus"], ["tabindex", "321"]], [
                                "\n\n                        ",
                            ]), "click", "showTransactionsScreen();"),
                            "\n                        ",
                            e("div", [["style", "float: left; width: 30px; height: 30px; "], ["id", "divTxnLoadingStatus"]], [
                                "\n                            ",
                                e("img", [["src", "assets/icons/loading.gif"], ["style", "width:30px;height:30px"]], []),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                    ",
                        e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [["class", "top_toggle"]], [
                                "\n                            ",
                                w(e("div", [["id", "toggle_trans_status_1"], ["class", "top_toggle_frame"], ["style", "cursor: pointer;"], ["role", "button"], ["tabindex", "322"]], [
                                    "\n                                ",
                                    e("div", [["class", "top_toggle_btn"], ["data-lang-key", "completed-transactions"]], [
                                        "Completed Transactions",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "top_toggle_btn_line"]], []),
                                    "\n                            ",
                                ]), "click", "toggleTransactionStatus(0)"),
                                "\n                            ",
                                w(e("div", [["id", "toggle_trans_status_2"], ["class", "top_toggle_frame disabled"], ["style", "cursor: pointer;"], ["role", "button"], ["tabindex", "323"]], [
                                    "\n                                ",
                                    e("div", [["class", "top_toggle_btn disabled"], ["data-lang-key", "pending-transactions"]], [
                                        "Pending Transactions",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "top_toggle_btn_line disabled"]], []),
                                    "\n                            ",
                                ]), "click", "toggleTransactionStatus(1)"),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "blocks-content scrollbar"], ["style", "text-align: left; overflow: auto ;"], ["id", "divCompleted"]], [
                                "\n                            ",
                                e("table", [["class", "styled-table"]], [
                                    "\n                                ",
                                    e("thead", [], [
                                        "\n                                    ",
                                        e("tr", [], [
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "inout"]], [
                                                "In/Out",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "coins"]], [
                                                "Coins",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "date"]], [
                                                "Date",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "from"]], [
                                                "From",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "to"]], [
                                                "To",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "hash"]], [
                                                "Hash",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("tbody", [["id", "tbodyComplextedTransactions"]], [
                                        "\n                                    ",
                                        e("tr", [["class", "completed-txn-in-row"]], [
                                            "\n                                        ",
                                            e("td", [], [
                                                e("img", [["src", "assets/svg/arrow-down-circle-outline.svg"], ["style", "width:30px;"]], []),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                "[VALUE]",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                "[DATE]",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_FROM]",
                                                ]), "click", "return OpenScanAddress('[FROM]');"),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_TO]",
                                                ]), "click", "return OpenScanAddress('[TO]');"),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_HASH]",
                                                ]), "click", "return OpenScanTxn('[HASH]');"),
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        e("tr", [["class", "completed-txn-out-row"]], [
                                            "\n                                        ",
                                            e("td", [], [
                                                e("img", [["src", "assets/svg/arrow-up-circle-outline.svg"], ["style", "width:30px;"]], []),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                "[VALUE]",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                "[DATE]",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_FROM]",
                                                ]), "click", "return OpenScanAddress('[FROM]');"),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_TO]",
                                                ]), "click", "return OpenScanAddress('[TO]');"),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_HASH]",
                                                ]), "click", "return OpenScanTxn('[HASH]');"),
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        e("tr", [["class", "failed-txn-in-row"]], [
                                            "\n                                        ",
                                            e("td", [], [
                                                "\n                                            ",
                                                e("img", [["src", "assets/svg/alert-outline.svg"], ["alt", "Failed"], ["style", "width: 30px;"]], []),
                                                "\n                                            ",
                                                e("img", [["src", "assets/svg/arrow-down-circle-outline.svg"], ["style", "width:30px;"]], []),
                                                "\n                                        ",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                "[VALUE]",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                "[DATE]",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_FROM]",
                                                ]), "click", "return OpenScanAddress('[FROM]');"),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_TO]",
                                                ]), "click", "return OpenScanAddress('[TO]');"),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_HASH]",
                                                ]), "click", "return OpenScanTxn('[HASH]');"),
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        e("tr", [["class", "failed-txn-out-row"]], [
                                            "\n                                        ",
                                            e("td", [], [
                                                "\n                                            ",
                                                e("img", [["src", "assets/svg/alert-outline.svg"], ["alt", "Failed"], ["style", "width: 30px;"]], []),
                                                "\n                                            ",
                                                e("img", [["src", "assets/svg/arrow-up-circle-outline.svg"], ["style", "width:30px;"]], []),
                                                "\n                                        ",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                "[VALUE]",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                "[DATE]",
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_FROM]",
                                                ]), "click", "return OpenScanAddress('[FROM]');"),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_TO]",
                                                ]), "click", "return OpenScanAddress('[TO]');"),
                                            ]),
                                            "\n                                        ",
                                            e("td", [], [
                                                w(e("a", [["href", "#"]], [
                                                    "[SHORT_HASH]",
                                                ]), "click", "return OpenScanTxn('[HASH]');"),
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n\n                        ",
                            e("div", [["class", "blocks-content scrollbar disabledhide"], ["style", "text-align: left; overflow: auto ;"], ["id", "divPending"]], [
                                "\n                            ",
                                e("table", [["class", "styled-table"]], [
                                    "\n                                ",
                                    e("thead", [], [
                                        "\n                                    ",
                                        e("tr", [], [
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "inout"]], [
                                                "In/Out",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "coins"]], [
                                                "Coins",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "date"]], [
                                                "Date",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "from"]], [
                                                "From",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "to"]], [
                                                "To",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "hash"]], [
                                                "Hash",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("tbody", [["id", "tbodyPendingTransactions"]], [
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n\n                        ",
                            e("div", [["class", "pagination-container"], ["style", "width: 30%;margin: auto;"]], [
                                "\n                            ",
                                w(e("div", [["class", "prev-container"], ["id", "divPrevTxnList"], ["role", "button"], ["tabindex", "720"]], [
                                    "\n\n                            ",
                                ]), "click", "return showPrevTxnPage();"),
                                "\n\n                            ",
                                w(e("div", [["class", "next-container "], ["id", "divNextTxnList"], ["role", "button"], ["tabindex", "721"]], [
                                    "\n\n                            ",
                                ]), "click", "return showNextTxnPage();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n\n            ",
                e("div", [["class", "center-content home-content"], ["id", "ValidatorScreen"], ["style", "margin-top:110px;"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "2308"]], [
                            "\n\n                    ",
                        ]), "click", "showSettingsScreen();"),
                        "\n                    ",
                        e("div", [["class", "roundex-box scrollbar"], ["style", "padding-top: 15px; padding-bottom: 15px;overflow-y: auto;overflow-x: auto;"]], [
                            "\n                        ",
                            e("div", [["class", "gas-header-row"]], [
                                "\n                            ",
                                e("div", [["class", "heading bold"], ["data-lang-key", "validator"]], [
                                    "Validator",
                                ]),
                                "\n                            ",
                                e("div", [["class", "gas-header-right"]], [
                                    "\n                                ",
                                    e("span", [["id", "spanValidatorGasFee"], ["class", "gas-fee-label"]], []),
                                    "\n                                ",
                                    w(e("div", [["id", "divValidatorGasIcon"], ["class", "gas-container"], ["role", "button"], ["tabindex", "2310"]], []), "click", "return onValidatorGasIconClick();"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "tab-name"], ["style", "color:black;"]], [
                                "\n                                ",
                                e("div", [["class", "divider"]], []),
                                "\n                                ",
                                e("label", [["data-lang-key", "validator-help"], ["style", "margin-top:5px"]], [
                                    "Use the following options to manage your validation. Use these options only if you want to run a validator node or if you are already running one.\n                                    You can check your validation status at: ",
                                ]),
                                w(e("a", [["href", "#"], ["id", "ahrefValidatorPage"], ["tabindex", "2309"]], [
                                    "link here",
                                ]), "click", "return openValidatorPage();"),
                                "\n                        ",
                            ]),
                            "\n\n                        ",
                            e("div", [["class", "input_container"], ["id", "divValidatorOptions"]], [
                                "\n                            ",
                                e("div", [["class", "selectwrapper"]], [
                                    "\n                                ",
                                    w(e("select", [["id", "ddlValidatorOptions"], ["class", "selectbox"], ["tabindex", "2300"]], [
                                        "\n                                    ",
                                        e("option", [["value", "none"]], [
                                            "(select an option)",
                                        ]),
                                        "\n                                    ",
                                        e("option", [["value", "newdeposit"]], [
                                            "New Validator Deposit",
                                        ]),
                                        "\n                                    ",
                                        e("option", [["value", "increasedeposit"]], [
                                            "Increase Deposit",
                                        ]),
                                        "\n                                    ",
                                        e("option", [["value", "initiatepartialwithdrawal"]], [
                                            "Initiate Partial Withdrawal",
                                        ]),
                                        "\n                                    ",
                                        e("option", [["value", "completepartialwithdrawal"]], [
                                            "Complete Partial Withdrawal",
                                        ]),
                                        "\n                                    ",
                                        e("option", [["value", "pausevalidation"]], [
                                            "Pause Validation",
                                        ]),
                                        "\n                                    ",
                                        e("option", [["value", "resumevalidation"]], [
                                            "Resume Validation",
                                        ]),
                                        "\n                                ",
                                    ]), "change", "updateValidatorScreen();"),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["id", "divValidatorAddress"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "validator-address"]], [
                                    "Validator Address",
                                ]),
                                "\n                            ",
                                e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 400;color:black;"], ["autocomplete", "off"], ["id", "txtValidatorAddress"], ["name", "validator_address"], ["data-placeholder-key", "validator-address"], ["placeholder", "Validator Address"], ["tabindex", "2301"]], []),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["id", "divValidatorDepositCoins"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "quantity"]], [
                                    "Quantity",
                                ]),
                                "\n                            ",
                                e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "number"], ["autocomplete", "off"], ["id", "txtValidatorDepositCoins"], ["name", "validator_deposit_coins"], ["data-placeholder-key", "quantity"], ["placeholder", "Quantity"], ["tabindex", "2302"]], []),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["id", "divCurrentNonceValidator"]], [
                                "\n                            ",
                                e("div", [["data-lang-key", "nonce-help"], ["style", "text-align: left;"]], []),
                                "\n                            ",
                                e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "number"], ["autocomplete", "off"], ["id", "txtCurrentNonceValidator"], ["name", "current_nonce_validator"], ["data-placeholder-key", "current-nonce"], ["placeholder", "Current Nonce"], ["tabindex", "2303"], ["maxlength", "6"]], []),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "input_container"], ["id", "divValidatorScreenPassword"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "enter-wallet-password"], ["style", "margin-top:5px"]], [
                                    "Enter Wallet Password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["style", "float: left; width: 80%;"]], [
                                        "\n                                    ",
                                        e("input", [["class", "tab-name"], ["style", "margin-top:5px; text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdValidator"], ["name", "password"], ["data-placeholder-key", "password"], ["placeholder", "password"], ["tabindex", "2304"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "float:left;margin-top:5px;"]], [
                                        "\n                                    ",
                                        w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["data-alt-key", "show-password"], ["role", "button"], ["tabindex", "2305"]], []), "click", "togglePasswordBox(this, 'pwdValidator');"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["style", "display: flex; justify-content: flex-end;"], ["id", "divValidatorButton"]], [
                                "\n\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "submit"], ["role", "button"], ["tabindex", "2306"], ["id", "btnValidation"], ["style", "float:right;"]], [
                                    "\n                                Submit\n                            ",
                                ]), "click", "return validation();"),
                                "\n                            ",
                                w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "sign-offline"], ["role", "button"], ["tabindex", "2307"], ["style", "margin-left:15px;float:right;"], ["id", "btnOfflineValidation"]], [
                                    "\n                                Offline Sign\n                            ",
                                ]), "click", "return validation();"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n\n            ",
                e("div", [["class", "tab-bar"], ["id", "tab-bar"]], [
                    "\n                ",
                    e("div", [["style", "display:flex; width:50%; margin:0 auto;"]], [
                        "\n                    ",
                        w(e("div", [["class", "tabbutton"], ["id", "tab1"], ["style", "display: flex;flex-direction: column;"], ["role", "button"], ["tabindex", "9"]], [
                            "\n                        ",
                            e("img", [["class", "tab-icon"], ["style", "align-self: center;"], ["src", "assets/svg/wallet-outline.svg"], ["alt", "Wallets Icon"]], []),
                            "\n                        ",
                            e("div", [["class", "tab-name"], ["style", "width: fit-content;align-self: center;"], ["data-lang-key", "wallets"]], [
                                "Wallets",
                            ]),
                            "\n                    ",
                        ]), "click", "showWalletListScreen();"),
                        w(e("div", [["class", "tabbutton"], ["id", "tab4"], ["style", "display: flex;flex-direction: column;"], ["role", "button"], ["tabindex", "12"]], [
                            "\n                        ",
                            e("img", [["class", "tab-icon"], ["style", "align-self: center;"], ["src", "assets/svg/settings.svg"], ["alt", "Settings Icon"]], []),
                            "\n                        ",
                            e("div", [["class", "tab-name"], ["style", "width: fit-content;align-self: center;"], ["data-lang-key", "settings"]], [
                                "Settings",
                            ]),
                            "\n                    ",
                        ]), "click", "showSettingsScreen();"),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n\n\n        ",
            ]),
            "\n\n\n    ",
        ]),
        t("\n\n    "),
        e("div", [["id", "settings-content"], ["class", "tabs-content"], ["style", "display: none;"]], [
            "\n\n        ",
            e("div", [["class", "content"], ["id", "settingsScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "4006"]], [
                            "\n\n                    ",
                        ]), "click", "showWalletScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box scrollbar"], ["style", "overflow-y: auto;overflow-x: auto;"]], [
                            "\n                        ",
                            e("div", [["class", "heading bold large"], ["data-lang-key", "settings"]], [
                                "Settings",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "vertical-menu"]], [
                                    "\n                                ",
                                    e("div", [["class", "vertical-menu-item"]], [
                                        "\n                                    ",
                                        w(e("a", [["href", "#"], ["data-lang-key", "wallet-path"], ["tabindex", "4000"], ["id", "ahrefWalletPath"]], [
                                            "Wallet Path",
                                        ]), "click", "return showWalletPath();"),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "divider"]], []),
                                    "\n                                ",
                                    e("div", [["class", "vertical-menu-item"]], [
                                        "\n                                    ",
                                        w(e("a", [["href", "#"], ["data-lang-key", "networks"], ["tabindex", "4001"]], [
                                            "Networks",
                                        ]), "click", "return showNetworksScreen();"),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "divider"]], []),
                                    "\n                                ",
                                    e("div", [["class", "vertical-menu-item"]], [
                                        "\n                                    ",
                                        w(e("a", [["href", "#"], ["data-lang-key", "offline-txn-signing"], ["tabindex", "4002"]], [
                                            "Offline Transaction Signing",
                                        ]), "click", "return showOfflineTxnSettingDialog();"),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "divider"]], []),
                                    "\n                                ",
                                    e("div", [["class", "vertical-menu-item"]], [
                                        "\n                                    ",
                                        w(e("a", [["href", "#"], ["data-lang-key", "signing"], ["tabindex", "4003"]], [
                                            "Signing",
                                        ]), "click", "return showAdvancedSigningSettingDialog();"),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "divider"]], []),
                                    "\n                                ",
                                    e("div", [["class", "vertical-menu-item"]], [
                                        "\n                                    ",
                                        w(e("a", [["href", "#"], ["data-lang-key", "validator-options"], ["tabindex", "4004"]], [
                                            "Validator Options",
                                        ]), "click", "return showValidatorScreen();"),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["class", "divider"]], []),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "networkListScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "3"]], [
                            "\n\n                    ",
                        ]), "click", "showSettingsScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [], [
                                "\n                            ",
                                e("div", [["class", "heading large"], ["style", "float:left;width:fit-content;"], ["data-lang-key", "networks"]], [
                                    "Networks",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "blocks-content scrollbar"], ["style", "text-align: left; overflow: auto ;max-height:380px;"], ["id", "divNetworkList"], ["tabindex", "1"]], [
                                "\n                            ",
                                e("table", [["class", "styled-table"]], [
                                    "\n                                ",
                                    e("thead", [], [
                                        "\n                                    ",
                                        e("tr", [], [
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "id"]], [
                                                "ID",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "name"]], [
                                                "Name",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "scan-api-url"]], [
                                                "Scan API URL",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "block-explorer-url"]], [
                                                "Block Explorer URL",
                                            ]),
                                            "\n                                        ",
                                            e("th", [["data-lang-key", "rpc-endpoint"]], [
                                                "RPC Endpoint",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("tbody", [["id", "tbodyNetworkRow"]], [
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["style", "align-content:center;"]], [
                                w(e("a", [["href", "#"], ["data-lang-key", "add-network"], ["tabindex", "2"]], [
                                    "Add Network",
                                ]), "click", "return showAddNetworkScreen();"),
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "networkAddScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "3"]], [
                            "\n\n                    ",
                        ]), "click", "showNetworksScreen()"),
                        "\n                    ",
                        e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                            "\n                        ",
                            e("div", [], [
                                "\n                            ",
                                e("div", [["class", "heading large"], ["style", "float:left;width:fit-content;"], ["data-lang-key", "add-network"]], [
                                    "Add Network",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "blocks-content scrollbar"], ["style", "text-align: left; overflow: auto ;"]], [
                                "\n                            ",
                                e("div", [["class", "input_container"]], [
                                    "\n\n                                ",
                                    e("div", [["class", "heading medium"], ["data-lang-key", "enter-network-json"]], [
                                        "Enter Blockchain Network JSON",
                                    ]),
                                    "\n                                ",
                                    e("div", [], [
                                        "\n                                    ",
                                        e("textarea", [["id", "txtNetworkJSON"], ["style", "width: 100%;"], ["rows", "9"], ["cols", "100"], ["tabindex", "1"]], [
                                            "{\n \"scanApiDomain\": \"readrelay.quantumcoinapi.com\",\n \"blockExplorerDomain\": \"quantumscan.com\",\n \"blockchainName\": \"QUANTUM COIN\",\n \"networkId\": 123123,\n \"rpcEndpoint\": \"public.rpc.quantumcoinapi.com\"\n}\n",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n\n                        ",
                            w(e("div", [["class", "large_button_container heading large"], ["style", "float:right;"], ["data-lang-key", "add"], ["role", "button"], ["tabindex", "2"]], [
                                "\n                            Add\n                        ",
                            ]), "click", "addNetwork();"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n\n    ",
        ]),
        t("\n\n    "),
        e("div", [["id", "wallets-content"], ["class", "tabs-content"], ["style", "display: none;"]], [
            "\n\n        ",
            e("div", [["class", "center-content home-content"], ["id", "WalletsScreen"]], [
                "\n\n            ",
                e("div", [["class", "center-content-rounded-container"], ["style", "width:95%;max-width: 95%;"]], [
                    "\n                ",
                    w(e("div", [["class", "back-container"], ["role", "button"], ["id", "backButtonWalletListScreen"]], [
                        "\n\n                ",
                    ]), "click", "showWalletScreen();"),
                    "\n                ",
                    e("div", [["class", "roundex-box"], ["style", "padding-top: 15px; padding-bottom: 15px;"]], [
                        "\n                    ",
                        e("div", [], [
                            "\n                        ",
                            e("div", [["class", "heading large"], ["style", "float:left;width:fit-content;"], ["data-lang-key", "wallets"]], [
                                "Wallets",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                    ",
                        e("div", [["class", "divider"]], []),
                        "\n                    ",
                        e("div", [["class", "blocks-content scrollbar"], ["style", "text-align: left; overflow: auto ;max-height:380px;"], ["id", "divWallets"]], [
                            "\n                        ",
                            e("table", [["class", "styled-table"]], [
                                "\n                            ",
                                e("thead", [], [
                                    "\n                                ",
                                    e("tr", [], [
                                        "\n                                    ",
                                        e("th", [["data-lang-key", "address"]], [
                                            "Address",
                                        ]),
                                        "\n                                    ",
                                        e("th", [["data-lang-key", "dpscan"]], [
                                            "DpScan",
                                        ]),
                                        "\n                                    ",
                                        e("th", [["data-lang-key", "backup"]], [
                                            "Backup",
                                        ]),
                                        "\n                                    ",
                                        e("th", [["data-lang-key", "reveal-seed"]], [
                                            "Reveal Seed",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("tbody", [["id", "tbodyWallet"]], [
                                    "\n                                ",
                                    e("tr", [["class", "wallet-row"]], [
                                        "\n                                    ",
                                        e("td", [], [
                                            w(e("a", [["href", "#"], ["tabindex", "[SHORT_ADDRESS_TAB_INDEX]"]], [
                                                "[SHORT_ADDRESS]",
                                            ]), "click", "setWalletAddressAndShowWalletScreen('[ADDRESS]');"),
                                        ]),
                                        "\n                                    ",
                                        e("td", [], [
                                            "\n                                        ",
                                            w(w(e("div", [["class", "button"], ["style", "background: #FF396F !important; border-radius: 10px; align-self: center; width: 35px; margin-left: 18px; "], ["role", "button"], ["tabindex", "[SCAN_TAB_INDEX]"]], [
                                                "\n                                            ",
                                                e("img", [["src", "assets/svg/open.svg"], ["alt", "DpScan"], ["style", "width: 25px; height: 25px; position: relative; top: 3px;"], ["data-alt-key", "dpscan"]], []),
                                                "\n                                        ",
                                            ]), "click", "OpenScanAddress('[ADDRESS]');"), "keypress", "clickOnEnter(event, this);"),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        e("td", [], [
                                            "\n                                        ",
                                            w(w(e("div", [["class", "button"], ["style", "background: green !important; border-radius: 10px; align-self: center; width: 35px; margin-left: 18px; "], ["role", "button"], ["tabindex", "[BACKUP_TAB_INDEX]"]], [
                                                "\n                                            ",
                                                e("img", [["src", "assets/svg/backup-outline.svg"], ["alt", "Backup"], ["style", "width: 25px; height: 25px; position: relative; top: 3px;"], ["data-alt-key", "backup"]], []),
                                                "\n                                        ",
                                            ]), "click", "showSpecificWalletBackupScreen('[ADDRESS]');"), "keypress", "clickOnEnter(event, this);"),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        e("td", [], [
                                            "\n                                        ",
                                            w(w(e("div", [["class", "button"], ["style", "background: #ff00db !important; border-radius: 10px; align-self: center; width: 35px; margin-left: 18px; "], ["role", "button"], ["tabindex", "[SEED_TAB_INDEX]"]], [
                                                "\n                                            ",
                                                e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Reveal Seed"], ["style", "width: 25px; height: 25px; position: relative; top: 3px;"], ["data-alt-key", "reveal-seed"]], []),
                                                "\n                                        ",
                                            ]), "click", "showRevealSeedScreen('[ADDRESS]');"), "keypress", "clickOnEnter(event, this);"),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n\n                    ",
                        e("div", [["class", "pagination-container"], ["style", "margin: auto;"]], [
                            "\n                        ",
                            w(e("a", [["href", "#"], ["data-lang-key", "create-or-restore-wallet"], ["id", "aCreateNewOrRestore"]], [
                                "Create New or Restore Existing Wallet",
                            ]), "click", "return createOrRestoreWallet();"),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "revealSeedScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["style", "max-width:650px;"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "6"]], [
                            "\n\n                    ",
                        ]), "click", "showWalletListScreen();"),
                        "\n                    ",
                        e("div", [["class", "roundex-box-middle scrollbar"], ["style", "padding-top: 15px; padding-bottom: 15px;overflow-y: auto;overflow-x:auto;"]], [
                            "\n                        ",
                            e("div", [], [
                                "\n                            ",
                                e("div", [["class", "heading large"], ["style", "float:left;width:fit-content;"], ["data-lang-key", "seed-words"]], [
                                    "Seed Words",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "heading medium"], ["id", "divRevealSeedAddress"], ["style", "font-size:12px;"]], [
                                "0xAa044ccF6BAD46F0de9fb4dF6b7d9fF02D2e195f",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["style", "width: fit-content; align-self: center;"]], [
                                "\n                            ",
                                e("div", [["style", "width:100%;text-align:left;"], ["id", "divRevealSeedHelp"]], [
                                    "\n                                ",
                                    e("div", [["class", "heading medium"], ["data-lang-key", "enter-wallet-password"]], [
                                        "Enter Wallet Password",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "width:100%;"]], [
                                        "\n                                    ",
                                        e("div", [["style", "float: left; width: 80%;"]], [
                                            "\n                                        ",
                                            e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdRevealSeedScreenPassword"], ["name", "password"], ["data-placeholder-key", "password"], ["placeholder", "Enter the password"], ["tabindex", "1"]], []),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        e("div", [["style", "float:left"]], [
                                            "\n                                        ",
                                            w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["style", "cursor:pointer;width:20px;"], ["role", "button"], ["tabindex", "2"]], []), "click", "togglePasswordBox(this, 'pwdRevealSeedScreenPassword');"),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n\n                                ",
                                    e("div", [["style", "text-align:left;margin-top:30px;"]], [
                                        "\n                                    ",
                                        e("div", [["class", "divider"]], []),
                                        "\n                                    ",
                                        e("ol", [], [
                                            "\n                                        ",
                                            e("li", [["style", "margin-bottom:5px;"], ["data-lang-key", "seed-words-info-1"]], [
                                                "Ensure that no one is looking at the screen other than you.",
                                            ]),
                                            "\n                                        ",
                                            e("li", [["style", "margin-bottom:5px;"], ["data-lang-key", "seed-words-info-2"]], [
                                                "Ensure that there is no camera pointed at this screen, including from your phone.",
                                            ]),
                                            "\n                                        ",
                                            e("li", [["style", "margin-bottom:5px;"], ["data-lang-key", "seed-words-info-3"]], [
                                                "You should save the seed words safely offline and keep multiple copies in a trustworthy and safe location.",
                                            ]),
                                            "\n                                        ",
                                            e("li", [["style", "margin-bottom:5px;"], ["data-lang-key", "seed-words-info-4"]], [
                                                "If these seed words are stolen or someone else gets access to them, your wallet is compromised.",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                    ",
                                        e("div", [["class", "divider"]], []),
                                        "\n\n\n                                    ",
                                        w(e("div", [["class", "large_button_container heading large"], ["data-lang-key", "reveal"], ["id", "divRevealButton"], ["style", "float:right;margin-top:10px;"], ["role", "button"], ["tabindex", "3"]], [
                                            "\n                                        Reveal\n                                    ",
                                        ]), "click", "showRevealSeedPanel()"),
                                        "\n\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n\n                            ",
                                e("div", [["class", "input_container scrollbar seedwrapper"], ["style", "overflow:auto;display:none;"], ["id", "divRevealSeedPanel"]], [
                                    "\n                                ",
                                    e("div", [["class", "tab-content mt-2"], ["style", "margin:auto;"]], [
                                        "\n                                    ",
                                        e("div", [["class", "tab-pane fade active show"], ["id", "revealseedpart"], ["role", "tabpanel"]], [
                                            "\n                                        ",
                                            e("div", [["class", "divSeedTable"]], [
                                                "\n                                            ",
                                                e("div", [["class", "divSeedBody"], ["tabindex", "4"]], [
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead1"], ["id", "revealSeedRowHead1"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "A1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow1"], ["id", "divRevealSeed0"]], [
                                                                "HELLOWORLD",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "A2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow1"], ["id", "divRevealSeed1"]], [
                                                                "AEROPLANE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "A3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow1"], ["id", "divRevealSeed2"]], [
                                                                "ALRIGHT",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "A4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow1"], ["id", "divRevealSeed3"]], [
                                                                "MOTIVATE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead2"], ["id", "revealSeedRowHead2"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "B1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow2"], ["id", "divRevealSeed4"]], [
                                                                "BICYCLE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "B2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow2"], ["id", "divRevealSeed5"]], [
                                                                "LOOPWARE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "B3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow2"], ["id", "divRevealSeed6"]], [
                                                                "DINGDONG",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "B4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow2"], ["id", "divRevealSeed7"]], [
                                                                "PINGPONG",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead3"], ["id", "revealSeedRowHead3"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "C1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow3"], ["id", "divRevealSeed8"]], [
                                                                "PINTHAT",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "C2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow3"], ["id", "divRevealSeed9"]], [
                                                                "POROTECH",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "C3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow3"], ["id", "divRevealSeed10"]], [
                                                                "MYSPIRIN",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "C4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow3"], ["id", "divRevealSeed11"]], [
                                                                "OKFINE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead4"], ["id", "revealSeedRowHead4"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "D1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow4"], ["id", "divRevealSeed12"]], [
                                                                "NAVY",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "D2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow4"], ["id", "divRevealSeed13"]], [
                                                                "ME",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "D3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow4"], ["id", "divRevealSeed14"]], [
                                                                "YES",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "D4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow4"], ["id", "divRevealSeed15"]], [
                                                                "WITHER",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead5"], ["id", "revealSeedRowHead5"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "E1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow5"], ["id", "divRevealSeed16"]], [
                                                                "OK",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "E2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow5"], ["id", "divRevealSeed17"]], [
                                                                "HIKE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "E3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow5"], ["id", "divRevealSeed18"]], [
                                                                "HELPWIRE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "E4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow5"], ["id", "divRevealSeed19"]], [
                                                                "CHOCOLATE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead6"], ["id", "revealSeedRowHead6"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "F1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow6"], ["id", "divRevealSeed20"]], [
                                                                "MILKSWEET",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "F2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow6"], ["id", "divRevealSeed21"]], [
                                                                "PIZZA",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "F3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow6"], ["id", "divRevealSeed22"]], [
                                                                "SUGAR",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "F4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow6"], ["id", "divRevealSeed23"]], [
                                                                "HONEY",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead7"], ["id", "revealSeedRowHead7"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "G1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow7"], ["id", "divRevealSeed24"]], [
                                                                "PINEAPPLE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "G2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow7"], ["id", "divRevealSeed25"]], [
                                                                "MANGO",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "G3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow7"], ["id", "divRevealSeed26"]], [
                                                                "HOSTLY",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "G4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow7"], ["id", "divRevealSeed27"]], [
                                                                "PINTBUG",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead8"], ["id", "revealSeedRowHead8"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "H1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow8"], ["id", "divRevealSeed28"]], [
                                                                "MICROWIN",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "H2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow8"], ["id", "divRevealSeed29"]], [
                                                                "MEGABIG",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "H3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow8"], ["id", "divRevealSeed30"]], [
                                                                "ALRIGHTY",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "H4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow8"], ["id", "divRevealSeed31"]], [
                                                                "WHYNOT",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead9"], ["id", "revealSeedRowHead9"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "I1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow9"], ["id", "divRevealSeed32"]], [
                                                                "HELLOWORLD",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "I2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow9"], ["id", "divRevealSeed33"]], [
                                                                "YOGHURT",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "I3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow9"], ["id", "divRevealSeed34"]], [
                                                                "SAUCE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "I4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow9"], ["id", "divRevealSeed35"]], [
                                                                "WHO",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead10"], ["id", "revealSeedRowHead10"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "J1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow10"], ["id", "divRevealSeed36"]], [
                                                                "WHOM",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "J2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow10"], ["id", "divRevealSeed37"]], [
                                                                "HOW",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "J3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow10"], ["id", "divRevealSeed38"]], [
                                                                "WHY",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "J4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow10"], ["id", "divRevealSeed39"]], [
                                                                "TAKECARE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead11"], ["id", "revealSeedRowHead11"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "K1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow11"], ["id", "divRevealSeed40"]], [
                                                                "BLITLINE",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "K2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow11"], ["id", "divRevealSeed41"]], [
                                                                "PIGHOPS",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "K3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow11"], ["id", "divRevealSeed42"]], [
                                                                "BUNTMECA",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "K4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow11"], ["id", "divRevealSeed43"]], [
                                                                "HASTILY",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                                ",
                                                    e("div", [["class", "seedrowhead12"], ["id", "revealSeedRowHead12"]], [
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "L1",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow12"], ["id", "divRevealSeed44"]], [
                                                                "PATIO",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "L2",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow12"], ["id", "divRevealSeed45"]], [
                                                                "LINTPICK",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "L3",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow12"], ["id", "divRevealSeed46"]], [
                                                                "NUTCRACK",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                    ",
                                                        e("div", [["class", "seedCell"]], [
                                                            "\n                                                        ",
                                                            e("div", [], [
                                                                "L4",
                                                            ]),
                                                            "\n                                                        ",
                                                            e("div", [["class", "seedrow12"], ["id", "divRevealSeed47"]], [
                                                                "QWERTY",
                                                            ]),
                                                            "\n                                                    ",
                                                        ]),
                                                        "\n                                                ",
                                                    ]),
                                                    "\n                                            ",
                                                ]),
                                                "\n                                        ",
                                            ]),
                                            "\n                                    ",
                                        ]),
                                        "\n                                ",
                                    ]),
                                    "\n\n\n                            ",
                                ]),
                                "\n\n                            ",
                                w(e("div", [["class", "copy-container"], ["role", "button"], ["style", "float:left;"], ["id", "divCopyRevealSeed"], ["tabindex", "5"]], []), "click", "copyRevealSeed()"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n        ",
            e("div", [["class", "content"], ["id", "backupSpecificWalletScreen"], ["style", "display: none;"]], [
                "\n            ",
                e("div", [["class", "center-content"]], [
                    "\n                ",
                    e("div", [["class", "center-content-rounded-container"], ["style", "max-width: 650px;"]], [
                        "\n                    ",
                        w(e("div", [["class", "back-container"], ["role", "button"], ["tabindex", "4"]], [
                            "\n\n                    ",
                        ]), "click", "showWalletListScreen();"),
                        "\n                    ",
                        e("div", [["class", "roundex-box-middle scrollbar"], ["style", "padding-top: 15px;padding-bottom: 15px;overflow-y: auto;overflow-x: auto;"]], [
                            "\n                        ",
                            e("div", [["class", "heading bold large"], ["data-lang-key", "backup-wallet"]], [
                                "Backup Wallet2",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "heading medium"], ["id", "divSpecificBackupAddress"], ["style", "font-size:12px;"]], []),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "heading large"]], [
                                "\n                            ",
                                e("p", [["data-lang-key", "backup-wallet-info-1"]], [
                                    "For additional safety, please make sure that you keep backup copies in atleast three different devices offline.",
                                ]),
                                "\n                            ",
                                e("p", [["data-lang-key", "backup-wallet-info-2"]], [
                                    "And remember you need the password to restore the backup!",
                                ]),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["class", "divider"]], []),
                            "\n                        ",
                            e("div", [["class", "input_container"]], [
                                "\n                            ",
                                e("div", [["class", "heading medium"], ["data-lang-key", "enter-wallet-password"]], [
                                    "Enter your wallet password",
                                ]),
                                "\n                            ",
                                e("div", [["style", "width:100%;"]], [
                                    "\n                                ",
                                    e("div", [["style", "float: left; width: 80%;"]], [
                                        "\n                                    ",
                                        e("input", [["class", "tab-name"], ["style", "text-align: left; width: 100%; border: none; outline: none; font-weight: 500; color: black; letter-spacing: 0.11em;"], ["type", "password"], ["autocomplete", "off"], ["id", "pwdBackupSpecificWallet"], ["name", "password"], ["placeholder", "Enter the password"], ["data-placeholder-key", "password"], ["tabindex", "1"]], []),
                                        "\n                                ",
                                    ]),
                                    "\n                                ",
                                    e("div", [["style", "float:left"]], [
                                        "\n                                    ",
                                        w(e("img", [["src", "assets/svg/eye-outline.svg"], ["alt", "Show Password"], ["data-alt-key", "show-password"], ["style", "cursor:pointer;width:20px;"], ["role", "button"], ["tabindex", "2"]], []), "click", "togglePasswordBox(this, 'pwdBackupSpecificWallet');"),
                                        "\n                                ",
                                    ]),
                                    "\n                            ",
                                ]),
                                "\n                            ",
                                e("div", [["class", "divider"]], []),
                                "\n                        ",
                            ]),
                            "\n                        ",
                            e("div", [["style", "display: flex; justify-content: flex-end;"]], [
                                "\n                            ",
                                w(e("div", [["id", "nextButtonSpecificWalletScreen"], ["class", "large_button_container heading large"], ["data-lang-key", "backup"], ["role", "button"], ["tabindex", "3"]], [
                                    "Backup",
                                ]), "click", "backupSpecificWallet()"),
                                "\n                        ",
                            ]),
                            "\n                    ",
                        ]),
                        "\n                ",
                    ]),
                    "\n            ",
                ]),
                "\n        ",
            ]),
            "\n\n    ",
        ]),
        t("\n\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n    "),
        t("\n\n    "),
        t("\n\n\n\n\n"),
    ];
}
