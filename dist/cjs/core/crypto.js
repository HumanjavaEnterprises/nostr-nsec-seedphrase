"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = sign;
exports.verify = verify;
exports.verifyWithResult = verifyWithResult;
exports.getSharedSecret = getSharedSecret;
exports.hmacSha256Sync = hmacSha256Sync;
exports.hmacSha256Async = hmacSha256Async;
exports.getEventHash = getEventHash;
exports.signEvent = signEvent;
exports.verifyEvent = verifyEvent;
exports.signMessage = signMessage;
exports.verifyMessage = verifyMessage;
exports.configureHMAC = configureHMAC;
const secp256k1_1 = require("@noble/curves/secp256k1");
const sha256_1 = require("@noble/hashes/sha256");
const hmac_1 = require("@noble/hashes/hmac");
const utils_1 = require("@noble/hashes/utils");
const logger_js_1 = __importDefault(require("../utils/logger.js"));
/**
 * Signs a message with a private key
 * @param {string} message - Message to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} Signature in hex format
 */
async function sign(message, privateKey) {
    try {
        const messageBytes = new TextEncoder().encode(message);
        const messageHash = (0, sha256_1.sha256)(messageBytes);
        const messageHashHex = (0, utils_1.bytesToHex)(messageHash);
        const signature = await secp256k1_1.schnorr.sign(messageHashHex, privateKey);
        return (0, utils_1.bytesToHex)(signature);
    }
    catch (error) {
        logger_js_1.default.error('Failed to sign message:', error?.toString());
        throw new Error('Failed to sign message');
    }
}
/**
 * Verifies a signature
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<boolean>} True if signature is valid
 */
async function verify(signature, message, publicKey) {
    try {
        const messageBytes = new TextEncoder().encode(message);
        const messageHash = (0, sha256_1.sha256)(messageBytes);
        const messageHashHex = (0, utils_1.bytesToHex)(messageHash);
        const isValid = await secp256k1_1.schnorr.verify((0, utils_1.hexToBytes)(signature), messageHashHex, (0, utils_1.hexToBytes)(publicKey));
        return isValid;
    }
    catch (error) {
        logger_js_1.default.error('Failed to verify signature:', error?.toString());
        return false;
    }
}
/**
 * Verifies a signature and returns a detailed result
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<ValidationResult>} Validation result with details
 */
async function verifyWithResult(signature, message, publicKey) {
    try {
        const isValid = await verify(signature, message, publicKey);
        return {
            isValid,
            error: isValid ? undefined : 'Invalid signature',
        };
    }
    catch (error) {
        logger_js_1.default.error('Failed to verify with result:', error?.toString());
        return {
            isValid: false,
            error: error?.toString() || 'Unknown error',
        };
    }
}
/**
 * Derives a shared secret using ECDH
 * @param {string} privateKey - Private key in hex format
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<Uint8Array>} Shared secret bytes
 */
async function getSharedSecret(privateKey, publicKey) {
    try {
        const privKeyBytes = (0, utils_1.hexToBytes)(privateKey);
        const pubKeyBytes = (0, utils_1.hexToBytes)(publicKey);
        const sharedPoint = secp256k1_1.schnorr.getPublicKey(privKeyBytes);
        return (0, sha256_1.sha256)(sharedPoint);
    }
    catch (error) {
        logger_js_1.default.error('Failed to get shared secret:', error?.toString());
        throw new Error('Failed to get shared secret');
    }
}
/**
 * Synchronously computes HMAC-SHA256
 * @param {Uint8Array} key - Key bytes
 * @param {Uint8Array} message - Message bytes
 * @returns {Uint8Array} HMAC bytes
 */
function hmacSha256Sync(key, message) {
    return hmac_1.hmac.create(sha256_1.sha256, key).update(message).digest();
}
/**
 * Asynchronously computes HMAC-SHA256
 * @param {Uint8Array} key - Key bytes
 * @param {Uint8Array} message - Message bytes
 * @returns {Promise<Uint8Array>} HMAC bytes
 */
async function hmacSha256Async(key, message) {
    return hmacSha256Sync(key, message);
}
/**
 * Calculates the event hash/ID according to the Nostr protocol
 * @param {UnsignedEvent} event - The unsigned event to hash
 * @returns {string} The event hash in hex format
 */
function getEventHash(event) {
    try {
        const serialized = JSON.stringify([
            0,
            event.pubkey,
            event.created_at,
            event.kind,
            event.tags,
            event.content,
        ]);
        const hash = (0, sha256_1.sha256)(new TextEncoder().encode(serialized));
        return (0, utils_1.bytesToHex)(hash);
    }
    catch (error) {
        logger_js_1.default.error('Failed to get event hash:', error?.toString());
        throw new Error('Failed to get event hash');
    }
}
/**
 * Signs an event with a private key
 * @param {UnsignedEvent} event - The unsigned event to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} The signature in hex format
 */
async function signEvent(event, privateKey) {
    try {
        const eventHash = getEventHash(event);
        const sig = await secp256k1_1.schnorr.sign(eventHash, privateKey);
        return (0, utils_1.bytesToHex)(sig);
    }
    catch (error) {
        logger_js_1.default.error('Failed to sign event:', error?.toString());
        throw new Error('Failed to sign event');
    }
}
/**
 * Verifies an event signature
 * @param {NostrEvent} event - The signed event to verify
 * @returns {Promise<boolean>} True if the signature is valid
 */
async function verifyEvent(event) {
    try {
        const hash = getEventHash({
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags,
            content: event.content,
        });
        return secp256k1_1.schnorr.verify((0, utils_1.hexToBytes)(event.sig), hash, (0, utils_1.hexToBytes)(event.pubkey));
    }
    catch (error) {
        logger_js_1.default.error('Failed to verify event:', error?.toString());
        return false;
    }
}
/**
 * Signs a message with a private key
 * @param {string} message - Message to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} The signature in hex format
 */
async function signMessage(message, privateKey) {
    try {
        const messageHash = (0, sha256_1.sha256)(new TextEncoder().encode(message));
        const messageHashHex = (0, utils_1.bytesToHex)(messageHash);
        const sig = await secp256k1_1.schnorr.sign(messageHashHex, privateKey);
        return (0, utils_1.bytesToHex)(sig);
    }
    catch (error) {
        logger_js_1.default.error('Failed to sign message:', error?.toString());
        throw new Error('Failed to sign message');
    }
}
/**
 * Verifies a message signature
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<boolean>} True if the signature is valid
 */
async function verifyMessage(signature, message, publicKey) {
    try {
        const messageHash = (0, sha256_1.sha256)(new TextEncoder().encode(message));
        const messageHashHex = (0, utils_1.bytesToHex)(messageHash);
        return await secp256k1_1.schnorr.verify((0, utils_1.hexToBytes)(signature), messageHashHex, (0, utils_1.hexToBytes)(publicKey));
    }
    catch (error) {
        logger_js_1.default.error('Failed to verify message:', error?.toString());
        return false;
    }
}
/**
 * Configures the HMAC functions for schnorr
 */
function configureHMAC() {
    try {
        secp256k1_1.schnorr.utils.hmacSha256Sync = hmacSha256Sync;
        secp256k1_1.schnorr.utils.hmacSha256Async = hmacSha256Async;
    }
    catch (error) {
        logger_js_1.default.error('Failed to configure HMAC:', error?.toString());
        throw new Error('Failed to configure HMAC');
    }
}
