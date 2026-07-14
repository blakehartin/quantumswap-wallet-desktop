import { ipcMain } from "electron";

export function registerSeedWordsHandlers(): void {
    ipcMain.handle("SeedWordsInitialize", async () => {
        const seedwords = require("seed-words");
        return await seedwords.initialize();
    });

    ipcMain.handle("SeedWordsGetAllWords", async () => {
        const seedwords = require("seed-words");
        return seedwords.getAllSeedWords();
    });

    ipcMain.handle("SeedWordsGetWordList", async (_event, data) => {
        const seedwords = require("seed-words");
        return seedwords.getWordListFromSeedArray(data);
    });

    ipcMain.handle("SeedWordsGetSeedArray", async (_event, data) => {
        const seedwords = require("seed-words");
        return seedwords.getSeedArrayFromWordList(data);
    });

    ipcMain.handle("SeedWordsDoesWordExist", async (_event, data) => {
        const seedwords = require("seed-words");
        return seedwords.doesSeedWordExist(data);
    });
}
