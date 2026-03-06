"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPublicKey = getPublicKey;
exports.fromHex = fromHex;
exports.generateKeyPairWithSeed = generateKeyPairWithSeed;
exports.seedPhraseToKeyPair = seedPhraseToKeyPair;
exports.seedPhraseToPrivateKey = seedPhraseToPrivateKey;
const secp256k1_js_1 = require("@noble/curves/secp256k1.js");
const utils_js_1 = require("@noble/hashes/utils.js");
const sha2_js_1 = require("@noble/hashes/sha2.js");
const pino_1 = require("pino");
const bip39_js_1 = require("../bips/bip39.js");
const nip_19_js_1 = require("../nips/nip-19.js");
const logger = (0, pino_1.pino)({
    level: process.env.LOG_LEVEL || "info",
    transport: {
        target: "pino-pretty",
        options: {
            colorize: true,
        },
    },
});
/**
 * Derives a public key from a private key
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The hex-encoded public key
 * @example
 * const pubkey = getPublicKey("1234567890abcdef...");
 * console.log(pubkey); // hex public key
 */
function getPublicKey(privateKey) {
    try {
        const pubkey = (0, utils_js_1.bytesToHex)(secp256k1_js_1.secp256k1.getPublicKey((0, utils_js_1.hexToBytes)(privateKey), true));
        return pubkey;
    }
    catch (error) {
        logger.error({ error }, "Failed to derive public key");
        throw new Error("Failed to derive public key");
    }
}
/**
 * Creates a key pair from a hex private key
 * @param {string} privateKeyHex - The hex-encoded private key
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the private key is invalid
 * @example
 * const keyPair = fromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
 * console.log(keyPair.publicKey); // corresponding public key
 * console.log(keyPair.nsec);      // bech32 nsec private key
 * console.log(keyPair.npub);      // bech32 npub public key
 */
function fromHex(privateKeyHex) {
    try {
        if (!privateKeyHex || privateKeyHex.length !== 64) {
            throw new Error("Invalid private key format");
        }
        const pubkeyHex = getPublicKey(privateKeyHex);
        const pubkeyBytes = (0, utils_js_1.hexToBytes)(pubkeyHex);
        const publicKey = {
            hex: pubkeyHex,
            compressed: pubkeyBytes,
            schnorr: pubkeyBytes.slice(1),
            npub: (0, nip_19_js_1.hexToNpub)(pubkeyHex),
        };
        const nsec = (0, nip_19_js_1.hexToNsec)(privateKeyHex);
        return {
            privateKey: privateKeyHex,
            publicKey,
            nsec,
            seedPhrase: "", // No seed phrase for hex-derived keys
        };
    }
    catch (error) {
        logger.error({ error }, "Failed to create key pair from hex");
        throw new Error("Failed to create key pair from hex");
    }
}
/**
 * Generates a new key pair with a random seed phrase
 * @returns {KeyPair} A new key pair containing private and public keys in various formats
 * @example
 * const keyPair = generateKeyPairWithSeed();
 * console.log(keyPair.seedPhrase); // random seed phrase
 * console.log(keyPair.privateKey);  // hex private key
 * console.log(keyPair.publicKey);   // hex public key
 */
function generateKeyPairWithSeed() {
    try {
        const seedPhrase = (0, bip39_js_1.generateSeedPhrase)();
        if (!(0, bip39_js_1.validateSeedPhrase)(seedPhrase)) {
            throw new Error("Generated invalid seed phrase");
        }
        return seedPhraseToKeyPair(seedPhrase);
    }
    catch (error) {
        logger.error({ error }, "Failed to generate key pair with seed");
        throw new Error("Failed to generate key pair with seed");
    }
}
/**
 * Converts a BIP39 seed phrase to a Nostr key pair
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 * @example
 * const keyPair = seedPhraseToKeyPair("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(keyPair.privateKey); // hex private key
 * console.log(keyPair.publicKey);  // hex public key
 * console.log(keyPair.nsec);       // bech32 nsec private key
 * console.log(keyPair.npub);       // bech32 npub public key
 */
function seedPhraseToKeyPair(seedPhrase) {
    try {
        if (!(0, bip39_js_1.validateSeedPhrase)(seedPhrase)) {
            throw new Error("Invalid seed phrase");
        }
        const privateKey = seedPhraseToPrivateKey(seedPhrase);
        const pubkeyHex = getPublicKey(privateKey);
        const pubkeyBytes = (0, utils_js_1.hexToBytes)(pubkeyHex);
        const publicKey = {
            hex: pubkeyHex,
            compressed: pubkeyBytes,
            schnorr: pubkeyBytes.slice(1),
            npub: (0, nip_19_js_1.hexToNpub)(pubkeyHex),
        };
        const nsec = (0, nip_19_js_1.hexToNsec)(privateKey);
        return {
            privateKey,
            publicKey,
            nsec,
            seedPhrase,
        };
    }
    catch (error) {
        logger.error({ error }, "Failed to convert seed phrase to key pair");
        throw new Error("Failed to convert seed phrase to key pair");
    }
}
/**
 * Converts a BIP39 seed phrase to a private key
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const privateKey = seedPhraseToPrivateKey("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(privateKey); // hex private key
 */
function seedPhraseToPrivateKey(seedPhrase) {
    try {
        if (!(0, bip39_js_1.validateSeedPhrase)(seedPhrase)) {
            throw new Error("Invalid seed phrase");
        }
        const entropy = (0, bip39_js_1.getEntropyFromSeedPhrase)(seedPhrase);
        const privateKey = (0, utils_js_1.bytesToHex)((0, sha2_js_1.sha256)(entropy));
        entropy.fill(0); // zero sensitive material
        return privateKey;
    }
    catch (error) {
        logger.error({ error }, "Failed to convert seed phrase to private key");
        throw new Error("Failed to convert seed phrase to private key");
    }
}
