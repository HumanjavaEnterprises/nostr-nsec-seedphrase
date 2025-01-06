"use strict";
/**
 * @module crypto/events
 * @description Event signing and verification functions for Nostr
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.getEventHash = getEventHash;
exports.createUnsignedEvent = createUnsignedEvent;
exports.signEvent = signEvent;
exports.verifyEvent = verifyEvent;
exports.signMessage = signMessage;
exports.verifySignature = verifySignature;
const secp256k1_1 = require("@noble/curves/secp256k1");
const sha256_1 = require("@noble/hashes/sha256");
const utils_1 = require("@noble/hashes/utils");
const logger_js_1 = require("../utils/logger.js");
const constants_js_1 = require("../constants.js");
/**
 * Calculates the event hash/ID according to the Nostr protocol
 * @param event - The event to hash
 * @returns The hex-encoded event hash
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
        return (0, utils_1.bytesToHex)((0, sha256_1.sha256)(new TextEncoder().encode(serialized)));
    }
    catch (error) {
        logger_js_1.logger.error('Failed to calculate event hash:', error);
        throw error;
    }
}
/**
 * Creates an unsigned event
 * @param pubkey - The public key of the event creator
 * @param content - The event content
 * @param kind - The event kind (defaults to TEXT_NOTE)
 * @param tags - The event tags (defaults to empty array)
 * @returns An unsigned event
 */
function createUnsignedEvent(pubkey, content, kind = constants_js_1.Defaults.KIND, tags = constants_js_1.Defaults.TAGS) {
    return {
        pubkey,
        created_at: constants_js_1.Defaults.CREATED_AT(),
        kind,
        tags,
        content,
    };
}
/**
 * Signs a Nostr event using Schnorr signatures
 * @param event - The event to sign
 * @param privateKey - The hex-encoded private key to sign with
 * @returns The signed event
 * @throws {Error} If signing fails
 */
async function signEvent(event, privateKey) {
    try {
        const id = getEventHash(event);
        const sig = (0, utils_1.bytesToHex)(await secp256k1_1.schnorr.sign((0, utils_1.hexToBytes)(id), (0, utils_1.hexToBytes)(privateKey)));
        logger_js_1.logger.log('Event signed successfully');
        return {
            ...event,
            id,
            sig,
        };
    }
    catch (error) {
        logger_js_1.logger.error('Failed to sign event:', error);
        throw error;
    }
}
/**
 * Verifies a Nostr event signature
 * @param event - The event to verify
 * @returns Validation result
 */
async function verifyEvent(event) {
    try {
        if (!event.id || !event.pubkey || !event.sig) {
            return {
                isValid: false,
                error: 'Missing required fields',
            };
        }
        const hash = getEventHash(event);
        if (hash !== event.id) {
            return {
                isValid: false,
                error: 'Event hash mismatch',
            };
        }
        logger_js_1.logger.log('Verifying event signature');
        const isValid = await secp256k1_1.schnorr.verify((0, utils_1.hexToBytes)(event.sig), (0, utils_1.hexToBytes)(hash), (0, utils_1.hexToBytes)(event.pubkey));
        return {
            isValid,
            error: isValid ? undefined : 'Invalid signature',
        };
    }
    catch (error) {
        logger_js_1.logger.error('Failed to verify event:', error);
        return {
            isValid: false,
            error: error instanceof Error ? error.message : 'Unknown error',
        };
    }
}
/**
 * Signs a message with a private key using Schnorr signatures
 * @param message - The message to sign
 * @param privateKey - The hex-encoded private key to sign with
 * @returns The hex-encoded signature
 * @throws {Error} If signing fails
 */
async function signMessage(message, privateKey) {
    try {
        const messageBytes = new TextEncoder().encode(message);
        const messageHash = (0, sha256_1.sha256)(messageBytes);
        const signature = await secp256k1_1.schnorr.sign(messageHash, (0, utils_1.hexToBytes)(privateKey));
        logger_js_1.logger.log('Message signed successfully');
        return (0, utils_1.bytesToHex)(signature);
    }
    catch (error) {
        logger_js_1.logger.error('Failed to sign message:', error);
        throw error;
    }
}
/**
 * Verifies a message signature using Schnorr verification
 * @param message - The original message
 * @param signature - The hex-encoded signature to verify
 * @param publicKey - The hex-encoded public key to verify against
 * @returns Validation result
 */
async function verifySignature(message, signature, publicKey) {
    try {
        const messageBytes = new TextEncoder().encode(message);
        const messageHash = (0, sha256_1.sha256)(messageBytes);
        logger_js_1.logger.log('Verifying message signature');
        const isValid = await secp256k1_1.schnorr.verify((0, utils_1.hexToBytes)(signature), messageHash, (0, utils_1.hexToBytes)(publicKey));
        return {
            isValid,
            error: isValid ? undefined : 'Invalid signature',
        };
    }
    catch (error) {
        logger_js_1.logger.error('Failed to verify signature:', error);
        return {
            isValid: false,
            error: error instanceof Error ? error.message : 'Unknown error',
        };
    }
}
