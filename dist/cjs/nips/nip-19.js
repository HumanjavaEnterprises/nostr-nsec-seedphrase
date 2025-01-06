"use strict";
/**
 * NIP-19: bech32-encoded entities
 * @module nip19
 * @description Implements NIP-19 specification for bech32-encoded entities in Nostr.
 * Provides encoding and decoding functions for npub (public keys), nsec (private keys),
 * and note (event IDs) formats.
 * @see https://github.com/nostr-protocol/nips/blob/master/19.md
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.hexToNpub = hexToNpub;
exports.hexToNsec = hexToNsec;
exports.hexToNote = hexToNote;
exports.decode = decode;
exports.nsecToHex = nsecToHex;
exports.npubToHex = npubToHex;
const logger_js_1 = require("../utils/logger.js");
const nostr_crypto_utils_1 = require("nostr-crypto-utils");
/**
 * Encodes a public key into npub format
 * @param {string} hex - The hex-encoded public key
 * @returns {string} The bech32-encoded npub string
 * @throws {Error} If encoding fails
 * @example
 * const npub = hexToNpub('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
 * returns 'npub1...'
 */
function hexToNpub(hex) {
    try {
        return (0, nostr_crypto_utils_1.npubEncode)(hex);
    }
    catch (error) {
        logger_js_1.logger.error({ error, hex }, 'Failed to encode public key to npub');
        throw error;
    }
}
/**
 * Encodes a private key into nsec format
 * @param {string} hex - The hex-encoded private key
 * @returns {string} The bech32-encoded nsec string
 * @throws {Error} If encoding fails
 * @security This function handles sensitive private key data
 * @example
 * const nsec = hexToNsec('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
 * returns 'nsec1...'
 */
function hexToNsec(hex) {
    try {
        return (0, nostr_crypto_utils_1.nsecEncode)(hex);
    }
    catch (error) {
        logger_js_1.logger.error({ error, hex }, 'Failed to encode private key to nsec');
        throw error;
    }
}
/**
 * Encodes an event ID into note format
 * @param {string} hex - The hex-encoded event ID
 * @returns {string} The bech32-encoded note string
 * @throws {Error} If encoding fails
 * @example
 * const note = hexToNote('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
 * returns 'note1...'
 */
function hexToNote(hex) {
    try {
        return (0, nostr_crypto_utils_1.noteEncode)(hex);
    }
    catch (error) {
        logger_js_1.logger.error({ error, hex }, 'Failed to encode event ID to note');
        throw error;
    }
}
/**
 * Decodes a bech32-encoded Nostr entity
 * @param {string} str - The bech32-encoded string (npub1, nsec1, or note1)
 * @returns {Nip19Data} Object containing the decoded type and data
 * @throws {Error} If decoding fails
 * @example
 * const result = decode('npub1...');
 * returns { type: 'npub', data: '...' }
 */
function decode(str) {
    try {
        return (0, nostr_crypto_utils_1.decode)(str);
    }
    catch (error) {
        logger_js_1.logger.error({ error, str }, 'Failed to decode bech32 string');
        throw error;
    }
}
/**
 * Converts a bech32 nsec private key to hex format
 * @param {string} nsec - The bech32-encoded nsec private key
 * @returns {string} The hex-encoded private key
 * @throws {Error} If conversion fails or input is invalid
 * @security This function handles sensitive private key data
 * @example
 * const hex = nsecToHex('nsec1...');
 * returns '3bf0c63f...'
 */
function nsecToHex(nsec) {
    try {
        const decoded = decode(nsec);
        if (decoded.type !== 'nsec') {
            throw new Error(`Invalid nsec format: ${nsec}`);
        }
        return decoded.data;
    }
    catch (error) {
        logger_js_1.logger.error({ error, nsec }, 'Failed to convert nsec to hex');
        throw error;
    }
}
/**
 * Converts a bech32 npub public key to hex format
 * @param {string} npub - The bech32-encoded npub public key
 * @returns {string} The hex-encoded public key
 * @throws {Error} If conversion fails or input is invalid
 * @example
 * const hex = npubToHex('npub1...');
 * returns '3bf0c63f...'
 */
function npubToHex(npub) {
    try {
        const decoded = decode(npub);
        if (decoded.type !== 'npub') {
            throw new Error(`Invalid npub format: ${npub}`);
        }
        return decoded.data;
    }
    catch (error) {
        logger_js_1.logger.error({ error, npub }, 'Failed to convert npub to hex');
        throw error;
    }
}
