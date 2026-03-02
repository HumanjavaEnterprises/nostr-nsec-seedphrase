"use strict";
/**
 * @module nips/nip-49
 * @description NIP-49 Private Key Encryption (ncryptsec) support
 * Converts between hex private keys and password-encrypted ncryptsec bech32 strings.
 * @see https://github.com/nostr-protocol/nips/blob/master/49.md
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.toNcryptsec = toNcryptsec;
exports.fromNcryptsec = fromNcryptsec;
const nostr_crypto_utils_1 = require("nostr-crypto-utils");
const utils_1 = require("@noble/hashes/utils");
const logger_js_1 = require("../utils/logger.js");
/**
 * Encrypts a hex private key into an ncryptsec bech32 string
 * @param {string} privateKeyHex - The hex-encoded private key (64 hex chars / 32 bytes)
 * @param {string} password - The password to encrypt with
 * @param {number} [logn=16] - Scrypt log2(N) parameter (higher = slower but more secure)
 * @returns {string} The bech32-encoded ncryptsec string
 * @throws {Error} If encryption fails
 * @example
 * const ncryptsec = toNcryptsec("1234567890abcdef...", "my-strong-password");
 * console.log(ncryptsec); // "ncryptsec1..."
 */
function toNcryptsec(privateKeyHex, password, logn = 16) {
    try {
        const secretBytes = (0, utils_1.hexToBytes)(privateKeyHex);
        const result = nostr_crypto_utils_1.nip49.encrypt(secretBytes, password, logn);
        secretBytes.fill(0); // zero sensitive material
        return result;
    }
    catch (error) {
        logger_js_1.logger.error("Failed to encrypt private key to ncryptsec:", error?.toString());
        throw error;
    }
}
/**
 * Decrypts an ncryptsec bech32 string back to a hex private key
 * @param {string} ncryptsec - The bech32-encoded ncryptsec string
 * @param {string} password - The password used for encryption
 * @returns {string} The hex-encoded private key
 * @throws {Error} If decryption fails (wrong password, invalid format, etc.)
 * @example
 * const privateKeyHex = fromNcryptsec("ncryptsec1...", "my-strong-password");
 * console.log(privateKeyHex); // "1234567890abcdef..."
 */
function fromNcryptsec(ncryptsec, password) {
    try {
        const secretBytes = nostr_crypto_utils_1.nip49.decrypt(ncryptsec, password);
        const hex = (0, utils_1.bytesToHex)(secretBytes);
        secretBytes.fill(0); // zero sensitive material
        return hex;
    }
    catch (error) {
        logger_js_1.logger.error("Failed to decrypt ncryptsec:", error?.toString());
        throw error;
    }
}
