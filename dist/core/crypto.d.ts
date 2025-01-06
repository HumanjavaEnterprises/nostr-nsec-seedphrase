import type { ValidationResult } from '../types/keys.js';
import type { NostrEvent, UnsignedEvent } from '../types/events.js';
/**
 * Signs a message with a private key
 * @param {string} message - Message to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} Signature in hex format
 */
export declare function sign(message: string, privateKey: string): Promise<string>;
/**
 * Verifies a signature
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<boolean>} True if signature is valid
 */
export declare function verify(signature: string, message: string, publicKey: string): Promise<boolean>;
/**
 * Verifies a signature and returns a detailed result
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<ValidationResult>} Validation result with details
 */
export declare function verifyWithResult(signature: string, message: string, publicKey: string): Promise<ValidationResult>;
/**
 * Derives a shared secret using ECDH
 * @param {string} privateKey - Private key in hex format
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<Uint8Array>} Shared secret bytes
 */
export declare function getSharedSecret(privateKey: string, publicKey: string): Promise<Uint8Array>;
/**
 * Synchronously computes HMAC-SHA256
 * @param {Uint8Array} key - Key bytes
 * @param {Uint8Array} message - Message bytes
 * @returns {Uint8Array} HMAC bytes
 */
export declare function hmacSha256Sync(key: Uint8Array, message: Uint8Array): Uint8Array;
/**
 * Asynchronously computes HMAC-SHA256
 * @param {Uint8Array} key - Key bytes
 * @param {Uint8Array} message - Message bytes
 * @returns {Promise<Uint8Array>} HMAC bytes
 */
export declare function hmacSha256Async(key: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
/**
 * Calculates the event hash/ID according to the Nostr protocol
 * @param {UnsignedEvent} event - The unsigned event to hash
 * @returns {string} The event hash in hex format
 */
export declare function getEventHash(event: UnsignedEvent): string;
/**
 * Signs an event with a private key
 * @param {UnsignedEvent} event - The unsigned event to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} The signature in hex format
 */
export declare function signEvent(event: UnsignedEvent, privateKey: string): Promise<string>;
/**
 * Verifies an event signature
 * @param {NostrEvent} event - The signed event to verify
 * @returns {Promise<boolean>} True if the signature is valid
 */
export declare function verifyEvent(event: NostrEvent): Promise<boolean>;
/**
 * Signs a message with a private key
 * @param {string} message - Message to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} The signature in hex format
 */
export declare function signMessage(message: string, privateKey: string): Promise<string>;
/**
 * Verifies a message signature
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<boolean>} True if the signature is valid
 */
export declare function verifyMessage(signature: string, message: string, publicKey: string): Promise<boolean>;
/**
 * Configures the HMAC functions for schnorr
 */
export declare function configureHMAC(): void;
