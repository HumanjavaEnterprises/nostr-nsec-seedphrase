/**
 * Converts a string to Uint8Array using UTF-8 encoding
 * @param {string} str - The string to convert
 * @returns {Uint8Array} The resulting bytes
 */
export declare function stringToBytes(str: string): Uint8Array;
/**
 * Converts a Uint8Array to string using UTF-8 encoding
 * @param {Uint8Array} bytes - The bytes to convert
 * @returns {string} The resulting string
 */
export declare function bytesToString(bytes: Uint8Array): string;
/**
 * Converts a hex string to base64
 * @param {string} hex - The hex string to convert
 * @returns {string} The base64 string
 */
export declare function hexToBase64(hex: string): string;
/**
 * Converts a base64 string to hex
 * @param {string} base64 - The base64 string to convert
 * @returns {string} The hex string
 */
export declare function base64ToHex(base64: string): string;
