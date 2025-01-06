"use strict";
/**
 * @module nips/nip-26
 * @description NIP-26 Delegated Event Signing implementation
 * @see https://github.com/nostr-protocol/nips/blob/master/26.md
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDelegation = createDelegation;
exports.isValidDelegation = isValidDelegation;
exports.getDelegationExpiry = getDelegationExpiry;
const secp256k1_1 = require("@noble/curves/secp256k1");
const sha256_1 = require("@noble/hashes/sha256");
const utils_1 = require("@noble/hashes/utils");
const logger_js_1 = require("../utils/logger.js");
/**
 * Creates a delegation token string
 * @param conditions - Delegation conditions
 * @returns Delegation token string
 */
function createDelegationString(delegator, delegatee, conditions) {
    const parts = ['nostr', 'delegation', delegator, delegatee];
    if (conditions.kinds) {
        parts.push(`kinds=${conditions.kinds.join(',')}`);
    }
    if (conditions.since) {
        parts.push(`created_at>${conditions.since}`);
    }
    if (conditions.until) {
        parts.push(`created_at<${conditions.until}`);
    }
    return parts.join(':');
}
/**
 * Creates a delegation token
 * @param delegatee - Public key of the delegatee
 * @param conditions - Delegation conditions
 * @param delegatorPrivateKey - Private key of the delegator
 * @returns Delegation token
 */
async function createDelegation(delegatee, conditions, delegatorPrivateKey) {
    try {
        // Get delegator's public key
        const delegator = (0, utils_1.bytesToHex)(secp256k1_1.schnorr.getPublicKey(delegatorPrivateKey));
        // Create delegation string
        const tokenString = createDelegationString(delegator, delegatee, conditions);
        // Sign the token
        const messageHash = (0, sha256_1.sha256)(new TextEncoder().encode(tokenString));
        const signature = await secp256k1_1.schnorr.sign(messageHash, delegatorPrivateKey);
        logger_js_1.logger.log('Created delegation token');
        return {
            delegator,
            delegatee,
            conditions,
            signature: (0, utils_1.bytesToHex)(signature),
        };
    }
    catch (error) {
        logger_js_1.logger.error('Failed to create delegation token:', error);
        throw error;
    }
}
/**
 * Verifies a delegation token
 * @param token - The delegation token to verify
 * @param now - Current Unix timestamp in seconds (optional, defaults to current time)
 * @returns Result of the validation
 */
async function verifyDelegation(token, now) {
    try {
        const tokenObject = JSON.parse(token);
        // Check conditions
        if (now) {
            if (tokenObject.conditions.since && now < tokenObject.conditions.since) {
                return {
                    isValid: false,
                    error: 'Event timestamp before delegation validity period',
                };
            }
            if (tokenObject.conditions.until && now > tokenObject.conditions.until) {
                return {
                    isValid: false,
                    error: 'Event timestamp after delegation validity period',
                };
            }
        }
        // Verify signature
        const tokenString = createDelegationString(tokenObject.delegator, tokenObject.delegatee, tokenObject.conditions);
        const messageHash = (0, sha256_1.sha256)(new TextEncoder().encode(tokenString));
        const isValid = await secp256k1_1.schnorr.verify(tokenObject.signature, messageHash, tokenObject.delegator);
        return {
            isValid,
            error: isValid ? undefined : 'Invalid delegation signature',
        };
    }
    catch (error) {
        logger_js_1.logger.error('Failed to verify delegation:', error);
        return { isValid: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}
/**
 * Checks if a delegation token is currently valid
 * @param token - The delegation token to check
 * @param now - Current Unix timestamp in seconds (optional, defaults to current time)
 * @returns True if the delegation is valid
 */
async function isValidDelegation(token, now) {
    const result = await verifyDelegation(token, now);
    return result.isValid;
}
/**
 * Gets the expiration time of a delegation token
 * @param token - Delegation token
 * @returns Expiration timestamp or undefined if no expiration
 */
function getDelegationExpiry(token) {
    const tokenObject = JSON.parse(token);
    return tokenObject.conditions.until;
}
