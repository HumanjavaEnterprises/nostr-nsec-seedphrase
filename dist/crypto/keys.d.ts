/**
 * @module crypto/keys
 * @description Key management functions for Nostr
 */
import { KeyPair, PublicKeyDetails, ValidationResult, PublicKey } from '../types/keys.js';
/**
 * Creates a PublicKeyDetails object from a hex string
 */
export declare function createPublicKey(hex: string): PublicKeyDetails;
/**
 * Generates a new BIP39 seed phrase
 * @returns A random 12-word BIP39 mnemonic seed phrase
 */
export declare function generateSeedPhrase(): string;
/**
 * Converts a BIP39 seed phrase to its entropy value
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns The entropy value
 * @throws {Error} If the seed phrase is invalid
 */
export declare function getEntropyFromSeedPhrase(seedPhrase: string): Uint8Array;
/**
 * Validates a BIP39 seed phrase
 * @param seedPhrase - The seed phrase to validate
 * @returns True if the seed phrase is valid, false otherwise
 */
export declare function validateSeedPhrase(seedPhrase: string): boolean;
/**
 * Converts a BIP39 seed phrase to a Nostr key pair
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 */
export declare function seedPhraseToKeyPair(seedPhrase: string): Promise<KeyPair>;
/**
 * Derives a private key from entropy
 * @param {Uint8Array} entropy - The entropy to derive from
 * @returns {string} The hex-encoded private key
 */
export declare function derivePrivateKey(entropy: Uint8Array): string;
/**
 * Generates a new key pair with a random seed phrase
 * @returns A new key pair containing private and public keys in various formats
 */
export declare function generateKeyPairWithSeed(): Promise<KeyPair>;
/**
 * Creates a key pair from a hex private key
 * @param privateKeyHex - The hex-encoded private key
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the private key is invalid
 */
export declare function fromHex(privateKeyHex: string): Promise<KeyPair>;
/**
 * Validates a key pair
 * @param publicKey - The public key to validate
 * @param privateKey - The private key to validate
 * @returns Validation result
 */
export declare function validateKeyPair(publicKey: PublicKey, privateKey: string): Promise<ValidationResult>;
/**
 * Validates a Nostr public key
 * @param publicKey - The public key to validate
 * @returns True if valid, false otherwise
 */
export declare function validatePublicKey(publicKey: string): boolean;
