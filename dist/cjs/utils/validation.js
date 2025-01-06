"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isValidHex = isValidHex;
exports.isValidTimestamp = isValidTimestamp;
exports.isBase64 = isBase64;
exports.isStringArray = isStringArray;
const logger_js_1 = require("./logger.js");
/**
 * Validates a hex string
 * @param {string} hex - The hex string to validate
 * @param {number} [expectedLength] - Optional expected length of the hex string
 * @returns {boolean} True if valid hex string, false otherwise
 */
function isValidHex(hex, expectedLength) {
    try {
        if (!hex)
            return false;
        if (!/^[0-9a-f]*$/i.test(hex))
            return false;
        if (expectedLength && hex.length !== expectedLength)
            return false;
        return true;
    }
    catch (error) {
        logger_js_1.logger.error('Hex validation failed:', error);
        return false;
    }
}
/**
 * Validates a timestamp is within a reasonable range
 * @param {number} timestamp - Unix timestamp in seconds
 * @param {number} [maxAgeDays=30] - Maximum age in days
 * @returns {boolean} True if timestamp is valid, false otherwise
 */
function isValidTimestamp(timestamp, maxAgeDays = 30) {
    try {
        const now = Math.floor(Date.now() / 1000);
        const maxAge = maxAgeDays * 24 * 60 * 60;
        return timestamp > (now - maxAge) && timestamp <= now;
    }
    catch (error) {
        logger_js_1.logger.error('Timestamp validation failed:', error);
        return false;
    }
}
/**
 * Checks if a string is base64 encoded
 * @param {string} str - The string to check
 * @returns {boolean} True if valid base64, false otherwise
 */
function isBase64(str) {
    try {
        return /^[A-Za-z0-9+/]*={0,2}$/.test(str);
    }
    catch (error) {
        logger_js_1.logger.error('Base64 validation failed:', error);
        return false;
    }
}
/**
 * Validates an array contains only strings
 * @param {unknown[]} arr - The array to validate
 * @returns {boolean} True if array contains only strings, false otherwise
 */
function isStringArray(arr) {
    try {
        return Array.isArray(arr) && arr.every(item => typeof item === 'string');
    }
    catch (error) {
        logger_js_1.logger.error('String array validation failed:', error);
        return false;
    }
}
