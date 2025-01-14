import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import logger from './logger.js';
/**
 * Converts a string to Uint8Array using UTF-8 encoding
 * @param {string} str - The string to convert
 * @returns {Uint8Array} The resulting bytes
 */
export function stringToBytes(str) {
    try {
        return new TextEncoder().encode(str);
    }
    catch (error) {
        logger.error('Failed to convert string to bytes:', error?.toString());
        throw new Error('Failed to convert string to bytes');
    }
}
/**
 * Converts a Uint8Array to string using UTF-8 encoding
 * @param {Uint8Array} bytes - The bytes to convert
 * @returns {string} The resulting string
 */
export function bytesToString(bytes) {
    try {
        return new TextDecoder().decode(bytes);
    }
    catch (error) {
        logger.error('Failed to convert bytes to string:', error?.toString());
        throw new Error('Failed to convert bytes to string');
    }
}
/**
 * Converts a hex string to base64
 * @param {string} hex - The hex string to convert
 * @returns {string} The base64 string
 */
export function hexToBase64(hex) {
    try {
        const bytes = hexToBytes(hex);
        return btoa(String.fromCharCode(...bytes));
    }
    catch (error) {
        logger.error('Failed to convert hex to base64:', error?.toString());
        throw new Error('Failed to convert hex to base64');
    }
}
/**
 * Converts a base64 string to hex
 * @param {string} base64 - The base64 string to convert
 * @returns {string} The hex string
 */
export function base64ToHex(base64) {
    try {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytesToHex(bytes);
    }
    catch (error) {
        logger.error('Failed to convert base64 to hex:', error?.toString());
        throw new Error('Failed to convert base64 to hex');
    }
}
