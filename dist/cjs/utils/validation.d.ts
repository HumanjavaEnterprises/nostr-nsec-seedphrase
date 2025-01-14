/**
 * Validates a hex string
 * @param {string} hex - The hex string to validate
 * @param {number} [expectedLength] - Optional expected length of the hex string
 * @returns {boolean} True if valid hex string, false otherwise
 */
export declare function isValidHex(hex: string, expectedLength?: number): boolean;
/**
 * Validates a timestamp is within a reasonable range
 * @param {number} timestamp - Unix timestamp in seconds
 * @param {number} [maxAgeDays=30] - Maximum age in days
 * @returns {boolean} True if timestamp is valid, false otherwise
 */
export declare function isValidTimestamp(timestamp: number, maxAgeDays?: number): boolean;
/**
 * Checks if a string is base64 encoded
 * @param {string} str - The string to check
 * @returns {boolean} True if valid base64, false otherwise
 */
export declare function isBase64(str: string): boolean;
/**
 * Validates an array contains only strings
 * @param {unknown[]} arr - The array to validate
 * @returns {boolean} True if array contains only strings, false otherwise
 */
export declare function isStringArray(arr: unknown[]): arr is string[];
