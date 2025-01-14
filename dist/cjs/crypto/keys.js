"use strict";
/**
 * @module crypto/keys
 * @description Key management functions for Nostr
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.createPublicKey = createPublicKey;
exports.generateSeedPhrase = generateSeedPhrase;
exports.getEntropyFromSeedPhrase = getEntropyFromSeedPhrase;
exports.validateSeedPhrase = validateSeedPhrase;
exports.seedPhraseToKeyPair = seedPhraseToKeyPair;
exports.derivePrivateKey = derivePrivateKey;
exports.generateKeyPairWithSeed = generateKeyPairWithSeed;
exports.fromHex = fromHex;
exports.validateKeyPair = validateKeyPair;
exports.validatePublicKey = validatePublicKey;
const bip39_1 = require("bip39");
const secp256k1_1 = require("@noble/curves/secp256k1");
const utils_1 = require("@noble/hashes/utils");
const sha256_1 = require("@noble/hashes/sha256");
const logger_js_1 = require("../utils/logger.js");
const nip_19_js_1 = require("../nips/nip-19.js");
/**
 * Gets the compressed public key (33 bytes with prefix)
 */
function getCompressedPublicKey(privateKeyBytes) {
    return secp256k1_1.secp256k1.getPublicKey(privateKeyBytes, true);
}
/**
 * Gets the schnorr public key (32 bytes x-coordinate) as per BIP340
 */
function getSchnorrPublicKey(privateKeyBytes) {
    return secp256k1_1.schnorr.getPublicKey(privateKeyBytes);
}
/**
 * Creates a PublicKeyDetails object from a hex string
 */
function createPublicKey(hex) {
    const bytes = (0, utils_1.hexToBytes)(hex);
    // For schnorr, we need to remove the first byte (compression prefix)
    const schnorrBytes = bytes.length === 33 ? bytes.slice(1) : bytes;
    return {
        hex,
        compressed: bytes.length === 33 ? bytes : getCompressedPublicKey(bytes),
        schnorr: schnorrBytes,
        npub: (0, nip_19_js_1.hexToNpub)(hex),
    };
}
/**
 * Generates a new BIP39 seed phrase
 * @returns A random 12-word BIP39 mnemonic seed phrase
 */
function generateSeedPhrase() {
    logger_js_1.logger.log('Generating new seed phrase');
    return (0, bip39_1.generateMnemonic)(128); // 12 words
}
/**
 * Converts a BIP39 seed phrase to its entropy value
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns The entropy value
 * @throws {Error} If the seed phrase is invalid
 */
function getEntropyFromSeedPhrase(seedPhrase) {
    try {
        if (!(0, bip39_1.validateMnemonic)(seedPhrase)) {
            throw new Error('Invalid seed phrase');
        }
        return (0, utils_1.hexToBytes)((0, bip39_1.mnemonicToEntropy)(seedPhrase));
    }
    catch (error) {
        logger_js_1.logger.error('Failed to get entropy from seed phrase:', error?.toString());
        throw error;
    }
}
/**
 * Validates a BIP39 seed phrase
 * @param seedPhrase - The seed phrase to validate
 * @returns True if the seed phrase is valid, false otherwise
 */
function validateSeedPhrase(seedPhrase) {
    logger_js_1.logger.log({ seedPhrase }, 'Validating seed phrase');
    const isValid = (0, bip39_1.validateMnemonic)(seedPhrase);
    logger_js_1.logger.log({ isValid }, 'Validated seed phrase');
    return Boolean(isValid);
}
/**
 * Converts a BIP39 seed phrase to a Nostr key pair
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 */
async function seedPhraseToKeyPair(seedPhrase) {
    try {
        if (!validateSeedPhrase(seedPhrase)) {
            throw new Error('Invalid seed phrase');
        }
        const entropy = getEntropyFromSeedPhrase(seedPhrase);
        const privateKey = derivePrivateKey(entropy);
        const publicKey = createPublicKey((0, utils_1.bytesToHex)(getCompressedPublicKey((0, utils_1.hexToBytes)(privateKey))));
        return {
            privateKey,
            publicKey,
            nsec: (0, nip_19_js_1.hexToNsec)(privateKey),
            seedPhrase,
        };
    }
    catch (error) {
        logger_js_1.logger.error('Failed to convert seed phrase to key pair:', error?.toString());
        throw error;
    }
}
/**
 * Derives a private key from entropy
 * @param {Uint8Array} entropy - The entropy to derive from
 * @returns {string} The hex-encoded private key
 */
function derivePrivateKey(entropy) {
    try {
        let privateKeyBytes = entropy;
        // Hash the entropy to get a valid private key
        privateKeyBytes = (0, sha256_1.sha256)(privateKeyBytes);
        return (0, utils_1.bytesToHex)(privateKeyBytes);
    }
    catch (error) {
        logger_js_1.logger.error('Failed to derive private key:', error?.toString());
        throw new Error('Failed to derive private key');
    }
}
/**
 * Generates a new key pair with a random seed phrase
 * @returns A new key pair containing private and public keys in various formats
 */
async function generateKeyPairWithSeed() {
    const seedPhrase = generateSeedPhrase();
    return seedPhraseToKeyPair(seedPhrase);
}
/**
 * Creates a key pair from a hex private key
 * @param privateKeyHex - The hex-encoded private key
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the private key is invalid
 */
async function fromHex(privateKeyHex) {
    try {
        const privateKeyBytes = (0, utils_1.hexToBytes)(privateKeyHex);
        if (!secp256k1_1.secp256k1.utils.isValidPrivateKey(privateKeyBytes)) {
            throw new Error('Invalid private key');
        }
        const publicKey = createPublicKey((0, utils_1.bytesToHex)(getCompressedPublicKey(privateKeyBytes)));
        return {
            privateKey: privateKeyHex,
            publicKey,
            nsec: (0, nip_19_js_1.hexToNsec)(privateKeyHex),
            seedPhrase: '', // No seed phrase for hex-imported keys
        };
    }
    catch (error) {
        logger_js_1.logger.error('Failed to create key pair from hex:', error?.toString());
        throw error;
    }
}
/**
 * Validates a key pair
 * @param publicKey - The public key to validate
 * @param privateKey - The private key to validate
 * @returns Validation result
 */
async function validateKeyPair(publicKey, privateKey) {
    try {
        const privateKeyBytes = (0, utils_1.hexToBytes)(privateKey);
        if (!secp256k1_1.secp256k1.utils.isValidPrivateKey(privateKeyBytes)) {
            return {
                isValid: false,
                error: 'Invalid private key',
            };
        }
        const pubKeyHex = typeof publicKey === 'string' ? publicKey : publicKey.hex;
        const derivedPublicKey = (0, utils_1.bytesToHex)(getCompressedPublicKey(privateKeyBytes));
        if (pubKeyHex !== derivedPublicKey) {
            return {
                isValid: false,
                error: 'Public key does not match private key',
            };
        }
        return {
            isValid: true,
        };
    }
    catch (error) {
        logger_js_1.logger.error('Failed to validate key pair:', error?.toString());
        return {
            isValid: false,
            error: error instanceof Error ? error.message : 'Unknown error',
        };
    }
}
/**
 * Validates a Nostr public key
 * @param publicKey - The public key to validate
 * @returns True if valid, false otherwise
 */
function validatePublicKey(publicKey) {
    try {
        const bytes = (0, utils_1.hexToBytes)(publicKey);
        return bytes.length === 32 || bytes.length === 33;
    }
    catch (error) {
        logger_js_1.logger.error('Failed to validate public key:', error?.toString());
        return false;
    }
}
