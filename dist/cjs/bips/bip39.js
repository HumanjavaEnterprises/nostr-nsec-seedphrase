"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateSeedPhrase = generateSeedPhrase;
exports.validateSeedPhrase = validateSeedPhrase;
exports.getEntropyFromSeedPhrase = getEntropyFromSeedPhrase;
const bip39_1 = require("bip39");
const logger_js_1 = require("../utils/logger.js");
/**
 * Generates a new BIP39 seed phrase
 * @returns {string} The generated seed phrase
 * @example
 * const seedPhrase = generateSeedPhrase();
 * console.log(seedPhrase); // "witch collapse practice feed shame open despair creek road again ice least"
 */
function generateSeedPhrase() {
    try {
        return (0, bip39_1.generateMnemonic)();
    }
    catch (error) {
        logger_js_1.logger.error('Failed to generate seed phrase:', error);
        throw new Error('Failed to generate seed phrase');
    }
}
/**
 * Validates a BIP39 seed phrase
 * @param {string} seedPhrase - The seed phrase to validate
 * @returns {boolean} True if the seed phrase is valid
 * @example
 * const isValid = validateSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(isValid); // true
 */
function validateSeedPhrase(seedPhrase) {
    try {
        return (0, bip39_1.validateMnemonic)(seedPhrase);
    }
    catch (error) {
        logger_js_1.logger.error('Failed to validate seed phrase:', error);
        return false;
    }
}
/**
 * Converts a BIP39 seed phrase to its entropy value
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {Uint8Array} The entropy value
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const entropy = getEntropyFromSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(entropy); // Uint8Array
 */
function getEntropyFromSeedPhrase(seedPhrase) {
    try {
        if (!validateSeedPhrase(seedPhrase)) {
            throw new Error('Invalid seed phrase');
        }
        // Convert the seed phrase to entropy bytes
        const entropyHex = (0, bip39_1.mnemonicToEntropy)(seedPhrase);
        // Convert hex string to Uint8Array
        const entropyBytes = new Uint8Array(entropyHex.length / 2);
        for (let i = 0; i < entropyHex.length; i += 2) {
            entropyBytes[i / 2] = parseInt(entropyHex.slice(i, i + 2), 16);
        }
        return entropyBytes;
    }
    catch (error) {
        logger_js_1.logger.error('Failed to get entropy from seed phrase:', error);
        throw new Error('Failed to get entropy from seed phrase');
    }
}
