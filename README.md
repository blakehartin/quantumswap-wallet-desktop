# QuantumSwap Desktop Wallet

QuantumSwap Desktop Wallets for Windows and Mac are built using Electron and TypeScript (no UI framework). This is a full TypeScript rebuild of the original vanilla-JS wallet; it is byte-compatible with wallets and settings created by earlier versions.

## Architecture

- `electron/` - main process (window creation, IPC handlers wrapping the `quantumcoin`, `quantumswap` and `seed-words` SDKs). Compiled with `tsc` to `dist/electron`.
- `src/` - renderer (sandboxed, no Node access; talks to the main process only through the whitelisted preload bridge).
  - `src/lib/` - storage, crypto, wallet, API and i18n modules.
  - `src/app/` - application logic (onboarding, wallet, send, swap, validator, settings, dialogs).
  - `src/ui/` - DOM primitives: `dom.ts` (typed `el()` builder + i18n `t()`), `screens.ts` (screen-module mounting); `autocomplete.ts` is the built-in replacement for the old autocomplete library.
  - `src/screens/` and `src/dialogs/` - hand-written typed screen/dialog modules (one per screen, mounted at bootstrap by `src/renderer.ts`).
- `public/` - verbatim legacy assets (styles.css, fonts, SVG icons, `json/en-us.json`, `json/blockchain-networks.json`) copied byte-for-byte into the build.

The renderer is bundled with Vite to `dist/renderer`; `electron-builder` packages `dist/`.

## Building

1) Install npm. For details see https://docs.npmjs.com/downloading-and-installing-node-js-and-npm
2) Install dependencies:

		npm install

3) To run the app:

		npm start

4) To create the build package:

		npm run publish

## Development

- `npm run build` - typecheck + bundle renderer + compile main process
- `npm test` - unit tests (includes storage byte-compatibility golden vectors)
- `npm run lint` - ESLint (bans `innerHTML`/`eval`-style sinks in the renderer)
- `npm run dist` - build and package locally without publishing

Set `OPEN_DEVTOOLS=1` to open DevTools on start.

## License

The source code is released under MIT license.

This project uses Ionic icons that are released under MIT License https://github.com/ionic-team/ionicons?tab=MIT-1-ov-file#readme

This project uses jquery-qrcode that is released under MIT License https://github.com/jeromeetienne/jquery-qrcode
