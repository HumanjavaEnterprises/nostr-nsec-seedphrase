/**
 * @module crypto/keys
 * @description Key management functions for Nostr
 */
import { KeyPair, PublicKeyDetails, ValidationResult, PublicKey } from "../types/keys.js";
/**
 * Creates a PublicKeyDetails object from a hex public key.
 *
 * The canonical Nostr identity is the 32-byte x-only key (BIP-340): `hex`,
 * `schnorr`, and `npub` all reflect that. `compressed` is the 33-byte SEC1
 * encoding kept only for non-Nostr interop.
 *
 * Accepts either a 32-byte x-only hex or a legacy 33-byte compressed hex; the
 * output is normalized to x-only.
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
 * NIP-06 derivation path: `m/44'/1237'/0'/0/0`.
 * @see https://github.com/nostr-protocol/nips/blob/master/06.md
 */
export declare const NIP06_DERIVATION_PATH = "m/44'/1237'/0'/0/0";
/**
 * Derives a Nostr private key from a BIP39 seed phrase per NIP-06:
 * BIP39 seed -> BIP32 master key -> derive `m/44'/1237'/0'/0/0`.
 * @param seedPhrase - A valid BIP39 mnemonic
 * @returns The hex-encoded 32-byte private key
 * @throws {Error} If the seed phrase is invalid or derivation fails
 */
export declare function deriveNip06PrivateKey(seedPhrase: string): string;
/**
 * Converts a BIP39 seed phrase to a Nostr key pair using the standard
 * NIP-06 derivation (BIP32 path `m/44'/1237'/0'/0/0`).
 *
 * NOTE (v0.8.0 BREAKING): prior versions derived the private key as
 * `sha256(bip39-entropy)`, which is NOT NIP-06. Identities created with
 * earlier versions can be recovered with {@link seedPhraseToKeyPairLegacy}.
 *
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 */
export declare function seedPhraseToKeyPair(seedPhrase: string): Promise<KeyPair>;
/**
 * LEGACY (pre-0.8.0) variant of {@link seedPhraseToKeyPair}: derives the
 * private key as `sha256(bip39-entropy)` instead of the NIP-06 BIP32 path.
 *
 * This is NOT NIP-06 and is NOT interoperable with other Nostr tooling. It
 * exists solely to recover identities created with nostr-nsec-seedphrase
 * before the NIP-06 fix in v0.8.0.
 *
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns The legacy key pair
 * @throws {Error} If the seed phrase is invalid
 */
export declare function seedPhraseToKeyPairLegacy(seedPhrase: string): Promise<KeyPair>;
/**
 * Derives a private key from entropy (legacy pre-0.8.0 scheme:
 * `sha256(entropy)`).
 * @deprecated Not NIP-06. Kept only for recovering pre-0.8.0 identities —
 *   see {@link seedPhraseToKeyPairLegacy}. Use {@link deriveNip06PrivateKey}
 *   for standard derivation.
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
