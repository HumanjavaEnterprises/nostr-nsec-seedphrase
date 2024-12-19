import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { validateMnemonic, generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import * as secp256k1 from "@noble/secp256k1";
import { bech32 } from 'bech32';
import { fromHex } from '../utils/encoding';

/**
 * NIP-06: Basic key derivation from mnemonic seed phrase
 * @see https://github.com/nostr-protocol/nips/blob/master/06.md
 */

const NOSTR_SEED_PATH = "m/44'/1237'/0'/0/0"; // Standard BIP-44 path for Nostr

/**
 * Interface for a Nostr key pair with associated formats
 */
export interface KeyPair {
  /** Private key in hex format */
  privateKey: string;
  /** Public key in hex format */
  publicKey: string;
  /** Private key in bech32 nsec format */
  nsec: string;
  /** Public key in bech32 npub format */
  npub: string;
  /** BIP39 seed phrase used to generate this key pair */
  seedPhrase?: string;
}

/**
 * Derive a private key from a mnemonic seed and optional passphrase
 * @param {Uint8Array} seed - The seed bytes from BIP-39 mnemonic
 * @param {string} [passphrase=''] - Optional passphrase for additional security
 * @returns {string} The derived private key in hex format
 */
export function derivePrivateKey(seed: Uint8Array, passphrase: string = ''): string {
  try {
    // Derive the master key using HMAC-SHA512
    const masterKey = hmac.create(sha256, 'Bitcoin seed');
    masterKey.update(seed);
    const masterKeyBytes = masterKey.digest();

    // Parse the derivation path
    const path = parsePath(NOSTR_SEED_PATH);
    
    // Derive the key through the path
    let key = masterKeyBytes;
    for (const index of path) {
      const indexBuffer = new Uint8Array(4);
      new DataView(indexBuffer.buffer).setUint32(0, index, false);
      
      const hmac = createHmac(key, 'key');
      hmac.update(indexBuffer);
      key = hmac.digest();
    }

    return bytesToHex(key);
  } catch (error) {
    console.error('Failed to derive private key:', error);
    throw error;
  }
}

/**
 * Parse a BIP-32 derivation path
 * @param {string} path - The derivation path (e.g., "m/44'/1237'/0'/0/0")
 * @returns {number[]} Array of indices
 */
function parsePath(path: string): number[] {
  if (!path.startsWith('m/')) {
    throw new Error('Invalid derivation path');
  }

  return path
    .slice(2)
    .split('/')
    .map(part => {
      if (part.endsWith("'")) {
        return parseInt(part.slice(0, -1)) + 0x80000000;
      }
      return parseInt(part);
    });
}

/**
 * Create an HMAC instance
 */
function createHmac(key: Uint8Array, message: string): ReturnType<typeof hmac.create> {
  const h = hmac.create(sha256, key);
  h.update(message);
  return h;
}

/**
 * Validate a BIP-39 mnemonic seed phrase
 * @param {string} mnemonic - The mnemonic seed phrase to validate
 * @returns {boolean} True if the mnemonic is valid, false otherwise
 */
export function validateSeedPhrase(mnemonic: string): boolean {
  try {
    return validateMnemonic(mnemonic, wordlist);
  } catch {
    return false;
  }
}

/**
 * Generate a new BIP-39 mnemonic seed phrase
 * @param {number} [strength=256] - The entropy length in bits (128-256)
 * @returns {string} The generated mnemonic seed phrase
 */
export function generateSeedPhrase(strength: number = 256): string {
  if (![128, 160, 192, 224, 256].includes(strength)) {
    throw new Error("Strength must be one of the following values: 128, 160, 192, 224, 256");
  }
  return generateMnemonic(wordlist);
}

/**
 * Derives a private key from a seed phrase.
 * @param {string} seedPhrase - The seed phrase to derive the key from
 * @returns {Promise<Uint8Array>} The generated private key
 */
export async function privateKeyFromSeed(seedPhrase: string): Promise<Uint8Array> {
  try {
    console.log('Converting seed phrase to seed:', seedPhrase);
    const seed = mnemonicToSeedSync(seedPhrase, ''); // Added empty passphrase parameter
    console.log('Derived seed:', seed);
    const privateKey = derivePrivateKey(seed);
    console.log('Derived private key:', privateKey);
    return new Uint8Array(Buffer.from(privateKey, 'hex'));
  } catch (error) {
    console.error('Failed to derive private key from seed:', error);
    throw error;
  }
}

/**
 * Convert a BIP39 seed phrase to a Nostr key pair
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 */
export async function seedPhraseToKeyPair(seedPhrase: string): Promise<KeyPair> {
  try {
    if (!validateSeedPhrase(seedPhrase)) {
      throw new Error("Invalid seed phrase");
    }

    const privateKey = await privateKeyFromSeed(seedPhrase);
    const publicKey = getPublicKeyFromSeed(bytesToHex(privateKey));
    
    return {
      privateKey: bytesToHex(privateKey),
      publicKey,
      nsec: hexToNsec(bytesToHex(privateKey)),
      npub: hexToNpub(publicKey),
      seedPhrase,
    };
  } catch (error) {
    console.error("Failed to create key pair from seed phrase:", error);
    throw error;
  }
}

/**
 * Generate a new key pair with a random seed phrase
 * @returns {KeyPair} A new key pair containing private and public keys in various formats
 */
export async function generateKeyPairWithSeed(): Promise<KeyPair> {
  const seedPhrase = generateSeedPhrase();
  return seedPhraseToKeyPair(seedPhrase);
}

/**
 * Create a key pair from a hex private key
 * @param {string} privateKeyHex - The hex-encoded private key
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the private key is invalid
 */
export function keyPairFromPrivateKey(privateKeyHex: string): KeyPair {
  try {
    // Convert hex to bytes using common utility
    const privateKeyBytes = fromHex(privateKeyHex);
    
    // Validate the private key
    if (!secp256k1.utils.isValidPrivateKey(privateKeyBytes)) {
      throw new Error('Invalid private key');
    }

    // Get the public key
    const publicKey = secp256k1.getPublicKey(privateKeyBytes, true);

    return {
      privateKey: privateKeyHex,
      publicKey: bytesToHex(publicKey),
      nsec: hexToNsec(privateKeyHex),
      npub: hexToNpub(bytesToHex(publicKey))
    };
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to create key pair: ${error.message}`);
    }
    throw new Error('Failed to create key pair: Unknown error');
  }
}

/**
 * Get the public key from a private key
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The hex-encoded public key
 * @throws {Error} If the private key is invalid
 */
export function getPublicKeyFromSeed(privateKey: string): string {
  try {
    return bytesToHex(secp256k1.getPublicKey(privateKey, true));
  } catch (error) {
    console.error("Failed to get public key:", error);
    throw error;
  }
}

/**
 * Convert a hex private key to bech32 nsec format
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The bech32-encoded private key
 */
function hexToNsec(privateKey: string): string {
  return bech32.encode('nsec', bech32.toWords(Buffer.from(privateKey, 'hex')));
}

/**
 * Convert a hex public key to bech32 npub format
 * @param {string} publicKey - The hex-encoded public key
 * @returns {string} The bech32-encoded public key
 */
function hexToNpub(publicKey: string): string {
  return bech32.encode('npub', bech32.toWords(Buffer.from(publicKey, 'hex')));
}

/**
 * Derive the public key from a seed phrase
 * @param {string} seedPhrase - The seed phrase to derive the public key from
 * @returns {Promise<string>} The derived public key
 */
export async function derivePublicKeyFromSeedPhrase(seedPhrase: string): Promise<string> {
  const keyPair = await seedPhraseToKeyPair(seedPhrase);
  return keyPair.publicKey;
}