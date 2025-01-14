/**
 * @module crypto/keys
 * @description Key management functions for Nostr
 */

import { generateMnemonic, validateMnemonic, mnemonicToEntropy } from 'bip39';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { logger } from '../utils/logger.js';
import { KeyPair, PublicKeyDetails, ValidationResult, PublicKey } from '../types/keys.js';
import { hexToNpub, hexToNsec } from '../nips/nip-19.js';

/**
 * Gets the compressed public key (33 bytes with prefix)
 */
function getCompressedPublicKey(privateKeyBytes: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(privateKeyBytes, true);
}

/**
 * Gets the schnorr public key (32 bytes x-coordinate) as per BIP340
 */
function getSchnorrPublicKey(privateKeyBytes: Uint8Array): Uint8Array {
  return schnorr.getPublicKey(privateKeyBytes);
}

/**
 * Creates a PublicKeyDetails object from a hex string
 */
export function createPublicKey(hex: string): PublicKeyDetails {
  const bytes = hexToBytes(hex);
  // For schnorr, we need to remove the first byte (compression prefix)
  const schnorrBytes = bytes.length === 33 ? bytes.slice(1) : bytes;

  return {
    hex,
    compressed: bytes.length === 33 ? bytes : getCompressedPublicKey(bytes),
    schnorr: schnorrBytes,
    npub: hexToNpub(hex),
  };
}

/**
 * Generates a new BIP39 seed phrase
 * @returns A random 12-word BIP39 mnemonic seed phrase
 */
export function generateSeedPhrase(): string {
  logger.log('Generating new seed phrase');
  return generateMnemonic(128); // 12 words
}

/**
 * Converts a BIP39 seed phrase to its entropy value
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns The entropy value
 * @throws {Error} If the seed phrase is invalid
 */
export function getEntropyFromSeedPhrase(seedPhrase: string): Uint8Array {
  try {
    if (!validateMnemonic(seedPhrase)) {
      throw new Error('Invalid seed phrase');
    }
    return hexToBytes(mnemonicToEntropy(seedPhrase));
  } catch (error) {
    logger.error('Failed to get entropy from seed phrase:', error?.toString());
    throw error;
  }
}

/**
 * Validates a BIP39 seed phrase
 * @param seedPhrase - The seed phrase to validate
 * @returns True if the seed phrase is valid, false otherwise
 */
export function validateSeedPhrase(seedPhrase: string): boolean {
  logger.log({ seedPhrase }, 'Validating seed phrase');
  const isValid = validateMnemonic(seedPhrase);
  logger.log({ isValid }, 'Validated seed phrase');
  return Boolean(isValid);
}

/**
 * Converts a BIP39 seed phrase to a Nostr key pair
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 */
export async function seedPhraseToKeyPair(seedPhrase: string): Promise<KeyPair> {
  try {
    if (!validateSeedPhrase(seedPhrase)) {
      throw new Error('Invalid seed phrase');
    }

    const entropy = getEntropyFromSeedPhrase(seedPhrase);
    const privateKey = derivePrivateKey(entropy);
    const publicKey = createPublicKey(bytesToHex(getCompressedPublicKey(hexToBytes(privateKey))));

    return {
      privateKey,
      publicKey,
      nsec: hexToNsec(privateKey),
      seedPhrase,
    };
  } catch (error) {
    logger.error('Failed to convert seed phrase to key pair:', error?.toString());
    throw error;
  }
}

/**
 * Derives a private key from entropy
 * @param {Uint8Array} entropy - The entropy to derive from
 * @returns {string} The hex-encoded private key
 */
export function derivePrivateKey(entropy: Uint8Array): string {
  try {
    let privateKeyBytes = entropy;
    // Hash the entropy to get a valid private key
    privateKeyBytes = sha256(privateKeyBytes);
    return bytesToHex(privateKeyBytes);
  } catch (error) {
    logger.error('Failed to derive private key:', error?.toString());
    throw new Error('Failed to derive private key');
  }
}

/**
 * Generates a new key pair with a random seed phrase
 * @returns A new key pair containing private and public keys in various formats
 */
export async function generateKeyPairWithSeed(): Promise<KeyPair> {
  const seedPhrase = generateSeedPhrase();
  return seedPhraseToKeyPair(seedPhrase);
}

/**
 * Creates a key pair from a hex private key
 * @param privateKeyHex - The hex-encoded private key
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the private key is invalid
 */
export async function fromHex(privateKeyHex: string): Promise<KeyPair> {
  try {
    const privateKeyBytes = hexToBytes(privateKeyHex);
    if (!secp256k1.utils.isValidPrivateKey(privateKeyBytes)) {
      throw new Error('Invalid private key');
    }
    const publicKey = createPublicKey(bytesToHex(getCompressedPublicKey(privateKeyBytes)));

    return {
      privateKey: privateKeyHex,
      publicKey,
      nsec: hexToNsec(privateKeyHex),
      seedPhrase: '', // No seed phrase for hex-imported keys
    };
  } catch (error) {
    logger.error('Failed to create key pair from hex:', error?.toString());
    throw error;
  }
}

/**
 * Validates a key pair
 * @param publicKey - The public key to validate
 * @param privateKey - The private key to validate
 * @returns Validation result
 */
export async function validateKeyPair(
  publicKey: PublicKey,
  privateKey: string,
): Promise<ValidationResult> {
  try {
    const privateKeyBytes = hexToBytes(privateKey);
    if (!secp256k1.utils.isValidPrivateKey(privateKeyBytes)) {
      return {
        isValid: false,
        error: 'Invalid private key',
      };
    }

    const pubKeyHex = typeof publicKey === 'string' ? publicKey : publicKey.hex;
    const derivedPublicKey = bytesToHex(getCompressedPublicKey(privateKeyBytes));

    if (pubKeyHex !== derivedPublicKey) {
      return {
        isValid: false,
        error: 'Public key does not match private key',
      };
    }

    return {
      isValid: true,
    };
  } catch (error) {
    logger.error('Failed to validate key pair:', error?.toString());
    return {
      isValid: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Validates a Nostr public key
 * @param publicKey - The public key to validate
 * @returns True if valid, false otherwise
 */
export function validatePublicKey(publicKey: string): boolean {
  try {
    const bytes = hexToBytes(publicKey);
    return bytes.length === 32 || bytes.length === 33;
  } catch (error) {
    logger.error('Failed to validate public key:', error?.toString());
    return false;
  }
}
