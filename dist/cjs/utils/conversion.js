"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.stringToBytes = stringToBytes;
exports.bytesToString = bytesToString;
exports.hexToBase64 = hexToBase64;
exports.base64ToHex = base64ToHex;
const utils_1 = require("@noble/hashes/utils");
const logger_js_1 = require("./logger.js");
/**
 * Converts a string to Uint8Array using UTF-8 encoding
 * @param {string} str - The string to convert
 * @returns {Uint8Array} The resulting bytes
 */
function stringToBytes(str) {
    try {
        return new TextEncoder().encode(str);
    }
    catch (error) {
        logger_js_1.logger.error('Failed to convert string to bytes:', error);
        throw new Error('Failed to convert string to bytes');
    }
}
/**
 * Converts a Uint8Array to string using UTF-8 encoding
 * @param {Uint8Array} bytes - The bytes to convert
 * @returns {string} The resulting string
 */
function bytesToString(bytes) {
    try {
        return new TextDecoder().decode(bytes);
    }
    catch (error) {
        logger_js_1.logger.error('Failed to convert bytes to string:', error);
        throw new Error('Failed to convert bytes to string');
    }
}
/**
 * Converts a hex string to base64
 * @param {string} hex - The hex string to convert
 * @returns {string} The base64 string
 */
function hexToBase64(hex) {
    try {
        const bytes = (0, utils_1.hexToBytes)(hex);
        return btoa(String.fromCharCode(...bytes));
    }
    catch (error) {
        logger_js_1.logger.error('Failed to convert hex to base64:', error);
        throw new Error('Failed to convert hex to base64');
    }
}
/**
 * Converts a base64 string to hex
 * @param {string} base64 - The base64 string to convert
 * @returns {string} The hex string
 */
function base64ToHex(base64) {
    try {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return (0, utils_1.bytesToHex)(bytes);
    }
    catch (error) {
        logger_js_1.logger.error('Failed to convert base64 to hex:', error);
        throw new Error('Failed to convert base64 to hex');
    }
}
