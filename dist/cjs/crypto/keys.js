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
const secp256k1_js_1 = require("@noble/curves/secp256k1.js");
const utils_js_1 = require("@noble/hashes/utils.js");
const sha2_js_1 = require("@noble/hashes/sha2.js");
const logger_js_1 = require("../utils/logger.js");
const nip_19_js_1 = require("../nips/nip-19.js");
/**
 * Gets the schnorr public key (32 bytes x-coordinate) as per BIP340
 */
function getSchnorrPublicKey(privateKeyBytes) {
    return secp256k1_js_1.schnorr.getPublicKey(privateKeyBytes);
}
/**
 * Creates a PublicKeyDetails object from a hex public key.
 *
 * The canonical Nostr identity is the 32-byte x-only key (BIP-340): `hex`,
 * `schnorr`, and `npub` all reflect that. `compressed` is the 33-byte SEC1
 * encoding kept only for non-Nostr interop.
 *
 * Accepts either a 32-byte x-only hex or a legacy 33-byte compressed hex; the
 * output is normalized to x-only.
 */
function createPublicKey(hex) {
    const bytes = (0, utils_js_1.hexToBytes)(hex);
    if (bytes.length === 32) {
        // x-only input. Reconstruct the compressed form assuming even Y per BIP-340.
        const compressed = new Uint8Array(33);
        compressed[0] = 0x02;
        compressed.set(bytes, 1);
        return {
            hex,
            compressed,
            schnorr: bytes,
            npub: (0, nip_19_js_1.hexToNpub)(hex),
        };
    }
    if (bytes.length === 33) {
        // Legacy compressed input: normalize to x-only.
        const schnorrBytes = bytes.slice(1);
        const xonlyHex = (0, utils_js_1.bytesToHex)(schnorrBytes);
        return {
            hex: xonlyHex,
            compressed: bytes,
            schnorr: schnorrBytes,
            npub: (0, nip_19_js_1.hexToNpub)(xonlyHex),
        };
    }
    throw new Error(`Invalid public key length: expected 32 (x-only) or 33 (compressed) bytes, got ${bytes.length}`);
}
/**
 * Generates a new BIP39 seed phrase
 * @returns A random 12-word BIP39 mnemonic seed phrase
 */
function generateSeedPhrase() {
    logger_js_1.logger.log("Generating new seed phrase");
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
            throw new Error("Invalid seed phrase");
        }
        return (0, utils_js_1.hexToBytes)((0, bip39_1.mnemonicToEntropy)(seedPhrase));
    }
    catch (error) {
        logger_js_1.logger.error("Failed to get entropy from seed phrase:", error?.toString());
        throw error;
    }
}
/**
 * Validates a BIP39 seed phrase
 * @param seedPhrase - The seed phrase to validate
 * @returns True if the seed phrase is valid, false otherwise
 */
function validateSeedPhrase(seedPhrase) {
    logger_js_1.logger.log("Validating seed phrase");
    const isValid = (0, bip39_1.validateMnemonic)(seedPhrase);
    logger_js_1.logger.log({ isValid }, "Validated seed phrase");
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
            throw new Error("Invalid seed phrase");
        }
        const entropy = getEntropyFromSeedPhrase(seedPhrase);
        const privateKey = derivePrivateKey(entropy);
        entropy.fill(0); // zero sensitive material
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKey);
        const publicKey = createPublicKey((0, utils_js_1.bytesToHex)(getSchnorrPublicKey(privateKeyBytes)));
        privateKeyBytes.fill(0); // zero sensitive material
        return {
            privateKey,
            publicKey,
            nsec: (0, nip_19_js_1.hexToNsec)(privateKey),
            seedPhrase,
        };
    }
    catch (error) {
        logger_js_1.logger.error("Failed to convert seed phrase to key pair:", error?.toString());
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
        // Hash the entropy to get a valid private key
        const privateKeyBytes = (0, sha2_js_1.sha256)(entropy);
        const hex = (0, utils_js_1.bytesToHex)(privateKeyBytes);
        privateKeyBytes.fill(0); // zero sensitive material
        return hex;
    }
    catch (error) {
        logger_js_1.logger.error("Failed to derive private key:", error?.toString());
        throw new Error("Failed to derive private key");
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
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKeyHex);
        if (!secp256k1_js_1.secp256k1.utils.isValidSecretKey(privateKeyBytes)) {
            privateKeyBytes.fill(0); // zero sensitive material
            throw new Error("Invalid private key");
        }
        const publicKey = createPublicKey((0, utils_js_1.bytesToHex)(getSchnorrPublicKey(privateKeyBytes)));
        privateKeyBytes.fill(0); // zero sensitive material
        return {
            privateKey: privateKeyHex,
            publicKey,
            nsec: (0, nip_19_js_1.hexToNsec)(privateKeyHex),
            seedPhrase: "", // No seed phrase for hex-imported keys
        };
    }
    catch (error) {
        logger_js_1.logger.error("Failed to create key pair from hex:", error?.toString());
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
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKey);
        if (!secp256k1_js_1.secp256k1.utils.isValidSecretKey(privateKeyBytes)) {
            privateKeyBytes.fill(0); // zero sensitive material
            return {
                isValid: false,
                error: "Invalid private key",
            };
        }
        const pubKeyHex = typeof publicKey === "string" ? publicKey : publicKey.hex;
        // Compare against the 32-byte x-only key (BIP-340 / Nostr identity).
        const derivedPublicKey = (0, utils_js_1.bytesToHex)(getSchnorrPublicKey(privateKeyBytes));
        privateKeyBytes.fill(0); // zero sensitive material
        if (pubKeyHex !== derivedPublicKey) {
            return {
                isValid: false,
                error: "Public key does not match private key",
            };
        }
        return {
            isValid: true,
        };
    }
    catch (error) {
        logger_js_1.logger.error("Failed to validate key pair:", error?.toString());
        return {
            isValid: false,
            error: error instanceof Error ? error.message : "Unknown error",
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
        const bytes = (0, utils_js_1.hexToBytes)(publicKey);
        // Nostr public keys are 32-byte x-only keys (BIP-340) only.
        return bytes.length === 32;
    }
    catch (error) {
        logger_js_1.logger.error("Failed to validate public key:", error?.toString());
        return false;
    }
}
