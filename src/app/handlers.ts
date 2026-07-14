// Registers the implementation for every legacy inline on*-handler code
// string that scripts/generate-views.mjs preserved from the old index.html
// (wired through w() in src/ui/views.generated.ts). The code strings are the
// registry keys, verbatim, so each binding stays traceable to the old markup.
//
// Handlers that contained template placeholders (e.g. '[ADDRESS]') only exist
// on nodes inside <template> rows / hidden template rows. The old app string-
// replaced those placeholders before inserting rows into the document; this
// port clones the template nodes and attaches real listeners in the row
// builders (app.ts), so these registrations can never fire — they are
// registered with the literal placeholder semantics for completeness.
import { registerHandlers } from "../ui/render";
import { inputById } from "./state";
import {
    OpenScanAddress,
    OpenScanTxn,
    addNetwork,
    backFromConfirmWalletScreen,
    backFromCreateOrRestoreWallet,
    backFromNewSeedScreen,
    backFromRestoreSeedScreen,
    backFromRestoreSeedTypeScreen,
    backFromWalletTypeScreen,
    backToCreateWalletPromptScreen,
    backToSeedScreen,
    backupCurrentWallet,
    backupSpecificWallet,
    checkNewPassword,
    clickOnEnter,
    copyAddress,
    copyAddressReceiveScreen,
    copyConfirmWalletAddress,
    copyNewSeed,
    copyRevealSeed,
    createOrRestoreWallet,
    nextFromConfirmWalletScreen,
    nextInfoStep,
    openBlockExplorerAccount,
    refreshAccountBalance,
    restoreSeed,
    restoreSeedTypeFormSubmitted,
    restoreWalletFromFile,
    selectTokenTab,
    setWalletAddressAndShowWalletScreen,
    showAddNetworkScreen,
    showNetworksScreen,
    showNextTxnPage,
    showPrevTxnPage,
    showReceiveScreen,
    showRevealSeedPanel,
    showRevealSeedScreen,
    showSeedPanel,
    showSettingsScreen,
    showSpecificWalletBackupScreen,
    showSwapScreen,
    showTransactionsScreen,
    showVerifySeedPanel,
    showWalletListScreen,
    showWalletPath,
    showWalletScreen,
    submitQuizForm,
    togglePasswordBox,
    toggleTransactionStatus,
    unlockWallet,
    verifySeedWords,
    verifyWalletPassword,
    walletFormSubmitted,
    walletTypeFormSubmitted,
} from "./app";
import { App } from "./state";
import {
    showAdvancedSigningSettingDialog,
    showNetworkDialog,
    showOfflineTxnSettingDialog,
} from "./dialog";
import {
    copySignedSendTransaction,
    onSendGasIconClick,
    onToggleSendUnrecognized,
    openOfflineTxnSigningUrl,
    sendCoins,
    showSendScreen,
    signOfflineSend,
    updateInfoSendScreen,
} from "./send";
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
    openAddAllowanceContractInExplorer,
    openRemoveAllowanceContractInExplorer,
    openSwapFromContractInExplorer,
    openSwapToContractInExplorer,
    setAddAllowanceQuantityToMax,
    setSwapFromQuantityToBalance,
    setSwapToQuantityToBalance,
    updateSwapScreenInfo,
} from "./swap";
import {
    copyOfflineSignature,
    onValidatorGasIconClick,
    openValidatorPage,
    showValidatorScreen,
    updateValidatorScreen,
    validation,
} from "./validator";

function check(id: string): () => void {
    return function () {
        inputById(id).checked = true;
    };
}

export function registerAppHandlers(): void {
    registerHandlers({
        // ---- change ----
        "onToggleSendUnrecognized();": () => onToggleSendUnrecognized(),
        "updateInfoSendScreen();": () => updateInfoSendScreen(),
        "updateSwapScreenInfo();": () => updateSwapScreenInfo(),
        "updateValidatorScreen();": () => updateValidatorScreen(),

        // ---- click: navigation / onboarding ----
        "nextInfoStep();": () => nextInfoStep(),
        "submitQuizForm()": () => submitQuizForm(),
        "walletFormSubmitted()": () => walletFormSubmitted(),
        "walletTypeFormSubmitted()": () => walletTypeFormSubmitted(),
        "backFromWalletTypeScreen()": () => backFromWalletTypeScreen(),
        "backFromNewSeedScreen()": () => backFromNewSeedScreen(),
        "restoreSeedTypeFormSubmitted()": () => restoreSeedTypeFormSubmitted(),
        "backFromRestoreSeedTypeScreen()": () => backFromRestoreSeedTypeScreen(),
        "backFromRestoreSeedScreen()": () => backFromRestoreSeedScreen(),
        "backToCreateWalletPromptScreen()": () => backToCreateWalletPromptScreen(),
        "backToSeedScreen()": () => backToSeedScreen(),
        "backFromCreateOrRestoreWallet()": () => backFromCreateOrRestoreWallet(),
        "return createOrRestoreWallet();": () => createOrRestoreWallet(),
        "return checkNewPassword();": () => checkNewPassword(),
        "copyNewSeed()": () => copyNewSeed(),
        "copyRevealSeed()": () => copyRevealSeed(),
        "return showSeedPanel();": () => showSeedPanel(),
        "showVerifySeedPanel()": () => showVerifySeedPanel(),
        "verifySeedWords();": () => verifySeedWords(),
        "verifyWalletPassword()": () => verifyWalletPassword(),
        "restoreSeed();": () => restoreSeed(),
        "restoreWalletFromFile();": () => restoreWalletFromFile(),
        "unlockWallet();": () => unlockWallet(),
        "return showWalletPath();": () => showWalletPath(),
        "backFromConfirmWalletScreen()": () => backFromConfirmWalletScreen(),
        "nextFromConfirmWalletScreen()": () => nextFromConfirmWalletScreen(),
        "return copyConfirmWalletAddress();": () => copyConfirmWalletAddress(),

        // ---- click: main screens ----
        "showWalletScreen()": () => showWalletScreen(),
        "showWalletScreen();": () => showWalletScreen(),
        "showReceiveScreen();": () => showReceiveScreen(),
        "showSendScreen();": () => showSendScreen(),
        "showSwapScreen();": () => showSwapScreen(),
        "showTransactionsScreen();": () => showTransactionsScreen(),
        "showSettingsScreen()": () => showSettingsScreen(),
        "showSettingsScreen();": () => showSettingsScreen(),
        "showWalletListScreen();": () => showWalletListScreen(),
        "showNetworksScreen()": () => showNetworksScreen(),
        "return showNetworksScreen();": () => showNetworksScreen(),
        "return showAddNetworkScreen();": () => showAddNetworkScreen(),
        "addNetwork();": () => addNetwork(),
        "refreshAccountBalance();": () => refreshAccountBalance(),
        "return copyAddress();": () => copyAddress(),
        "return copyAddressReceiveScreen();": () => copyAddressReceiveScreen(),
        "return openBlockExplorerAccount();": () => openBlockExplorerAccount(),
        "backupCurrentWallet()": () => backupCurrentWallet(),
        "backupSpecificWallet()": () => backupSpecificWallet(),
        "showRevealSeedPanel()": () => showRevealSeedPanel(),
        "return selectTokenTab(true);": () => selectTokenTab(true),
        "return selectTokenTab(false);": () => selectTokenTab(false),
        "toggleTransactionStatus(0)": () => toggleTransactionStatus(0),
        "toggleTransactionStatus(1)": () => toggleTransactionStatus(1),
        "return showPrevTxnPage();": () => showPrevTxnPage(),
        "return showNextTxnPage();": () => showNextTxnPage(),
        "setWalletAddressAndShowWalletScreen(currentWalletAddress)": () => setWalletAddressAndShowWalletScreen(App.currentWalletAddress),
        "return setWalletAddressAndShowWalletScreen(currentWalletAddress);": () => setWalletAddressAndShowWalletScreen(App.currentWalletAddress),

        // ---- click: dialogs / settings ----
        "return showNetworkDialog();": () => showNetworkDialog(),
        "return showOfflineTxnSettingDialog();": () => showOfflineTxnSettingDialog(),
        "return showAdvancedSigningSettingDialog();": () => showAdvancedSigningSettingDialog(),

        // ---- click: send / offline signing ----
        "return sendCoins();": () => sendCoins(),
        "return signOfflineSend();": () => signOfflineSend(),
        "copySignedSendTransaction()": () => copySignedSendTransaction(),
        "return openOfflineTxnSigningUrl();": () => openOfflineTxnSigningUrl(),
        "return onSendGasIconClick();": () => onSendGasIconClick(),

        // ---- click: swap ----
        "onSwapScreenBackClick();": () => onSwapScreenBackClick(),
        "return onSwapNextClick();": () => onSwapNextClick(),
        "return onSwapConfirmNextClick();": () => onSwapConfirmNextClick(),
        "return onSwapGasIconClick();": () => onSwapGasIconClick(),
        "return onSwapConfirmGasIconClick();": () => onSwapConfirmGasIconClick(),
        "return onSwapSuccessOkClick();": () => onSwapSuccessOkClick(),
        "return setSwapFromQuantityToBalance();": () => setSwapFromQuantityToBalance(),
        "return setSwapToQuantityToBalance();": () => setSwapToQuantityToBalance(),
        "copySwapFromContractAddress();": () => copySwapFromContractAddress(),
        "copySwapToContractAddress();": () => copySwapToContractAddress(),
        "openSwapFromContractInExplorer(); return false;": () => { openSwapFromContractInExplorer(); return false; },
        "openSwapToContractInExplorer(); return false;": () => { openSwapToContractInExplorer(); return false; },
        "return onRemoveSwapAllowanceClick();": () => onRemoveSwapAllowanceClick(),
        "return onRemoveAllowanceRemoveClick();": () => onRemoveAllowanceRemoveClick(),
        "return onRemoveAllowanceGasIconClick();": () => onRemoveAllowanceGasIconClick(),
        "openRemoveAllowanceContractInExplorer(); return false;": () => { openRemoveAllowanceContractInExplorer(); return false; },
        "return onAddAllowanceAddClick();": () => onAddAllowanceAddClick(),
        "return onAddAllowanceGasIconClick();": () => onAddAllowanceGasIconClick(),
        "return setAddAllowanceQuantityToMax();": () => setAddAllowanceQuantityToMax(),
        "openAddAllowanceContractInExplorer(); return false;": () => { openAddAllowanceContractInExplorer(); return false; },

        // ---- click: validator ----
        "return showValidatorScreen();": () => showValidatorScreen(),
        "return validation();": () => validation(),
        "return onValidatorGasIconClick();": () => onValidatorGasIconClick(),
        "return openValidatorPage();": () => openValidatorPage(),
        "copyOfflineSignature()": () => copyOfflineSignature(),

        // ---- click: radio label helpers (verbatim legacy one-liners) ----
        "document.getElementById('optNewWallet').checked  = true;": check("optNewWallet"),
        "document.getElementById('optRestoreWalletFromSeed').checked = true;": check("optRestoreWalletFromSeed"),
        "document.getElementById('optRestoreWalletFromBackupFile').checked = true;": check("optRestoreWalletFromBackupFile"),
        "document.getElementById('optSeedLength32').checked = true;": check("optSeedLength32"),
        "document.getElementById('optSeedLength36').checked = true;": check("optSeedLength36"),
        "document.getElementById('optSeedLength48').checked = true;": check("optSeedLength48"),
        "document.getElementById('optWalletTypeDefault').checked = true;": check("optWalletTypeDefault"),
        "document.getElementById('optWalletTypeAdvanced').checked = true;": check("optWalletTypeAdvanced"),
        "document.getElementById('optOfflineTxnSigningEnabled').checked  = true;": check("optOfflineTxnSigningEnabled"),
        "document.getElementById('optOfflineTxnSigningDisabled').checked  = true;": check("optOfflineTxnSigningDisabled"),
        "document.getElementById('optAdvancedSigningEnabled').checked  = true;": check("optAdvancedSigningEnabled"),
        "document.getElementById('optAdvancedSigningDisabled').checked  = true;": check("optAdvancedSigningDisabled"),

        // ---- click: password eye toggles ----
        "togglePasswordBox(this, 'pwdPassword');": (element) => togglePasswordBox(element, "pwdPassword"),
        "togglePasswordBox(this, 'pwdRetypePassword');": (element) => togglePasswordBox(element, "pwdRetypePassword"),
        "togglePasswordBox(this, 'pwdVerifyWalletPassword');": (element) => togglePasswordBox(element, "pwdVerifyWalletPassword"),
        "togglePasswordBox(this, 'pwdUnlock');": (element) => togglePasswordBox(element, "pwdUnlock"),
        "togglePasswordBox(this, 'pwdRestoreWallet');": (element) => togglePasswordBox(element, "pwdRestoreWallet"),
        "togglePasswordBox(this, 'pwdSend');": (element) => togglePasswordBox(element, "pwdSend"),
        "togglePasswordBox(this, 'pwdSwapConfirm');": (element) => togglePasswordBox(element, "pwdSwapConfirm"),
        "togglePasswordBox(this, 'pwdRemoveAllowance');": (element) => togglePasswordBox(element, "pwdRemoveAllowance"),
        "togglePasswordBox(this, 'pwdAddAllowance');": (element) => togglePasswordBox(element, "pwdAddAllowance"),
        "togglePasswordBox(this, 'pwdValidator');": (element) => togglePasswordBox(element, "pwdValidator"),
        "togglePasswordBox(this, 'pwdRevealSeedScreenPassword');": (element) => togglePasswordBox(element, "pwdRevealSeedScreenPassword"),
        "togglePasswordBox(this, 'pwdBackupSpecificWallet');": (element) => togglePasswordBox(element, "pwdBackupSpecificWallet"),
        "togglePasswordBox(this, 'txtTxReviewPassword');": (element) => togglePasswordBox(element, "txtTxReviewPassword"),

        // ---- input ----
        "debouncedUpdateToQuantityFromFrom();": () => debouncedUpdateToQuantityFromFrom(),
        "debouncedUpdateFromQuantityFromTo();": () => debouncedUpdateFromQuantityFromTo(),
        "onAddAllowanceQuantityInput();": () => onAddAllowanceQuantityInput(),

        // ---- keydown / keypress ----
        "if(event.key==='Enter'||event.key===' '){event.preventDefault(); document.getElementById('chkSendShowUnrecognized').click();}":
            (_element, event) => {
                const key = (event as KeyboardEvent).key;
                if (key === "Enter" || key === " ") {
                    event.preventDefault();
                    inputById("chkSendShowUnrecognized").click();
                }
            },
        "clickOnEnter(event, this);": (element, event) => clickOnEnter(event, element),

        // ---- template-row placeholders (never fire; see module comment) ----
        "OpenScanAddress('[ADDRESS]');": () => OpenScanAddress("[ADDRESS]"),
        "return OpenScanAddress('[FROM]');": () => OpenScanAddress("[FROM]"),
        "return OpenScanAddress('[TO]');": () => OpenScanAddress("[TO]"),
        "return OpenScanAddress('[TOKEN_CONTRACT]');": () => OpenScanAddress("[TOKEN_CONTRACT]"),
        "return OpenScanTxn('[HASH]');": () => OpenScanTxn("[HASH]"),
        "setWalletAddressAndShowWalletScreen('[ADDRESS]');": () => setWalletAddressAndShowWalletScreen("[ADDRESS]"),
        "showSpecificWalletBackupScreen('[ADDRESS]');": () => showSpecificWalletBackupScreen("[ADDRESS]"),
        "showRevealSeedScreen('[ADDRESS]');": () => showRevealSeedScreen("[ADDRESS]"),
    });
}
