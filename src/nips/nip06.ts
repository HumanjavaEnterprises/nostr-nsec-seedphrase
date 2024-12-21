import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { validateMnemonic, generateMnemonic, mnemonicToSeedSync } from 'bip39';
import { getPublicKey, validatePrivateKey, validatePublicKey } from '../crypto/keys';
import { hexToNsec, hexToNpub } from './nip19';

// Nostr BIP-32 derivation path (m/44'/1237'/0'/0/0)
const NOSTR_PATH = "m/44'/1237'/0'/0/0";

// BIP-32 constants
const HARDENED_OFFSET = 0x80000000;
const MASTER_SECRET = Buffer.from('Bitcoin seed', 'utf8');

// Nostr BIP-32 derivation path (m/44'/1237'/0'/0/0)
const NOSTR_BIP32_PATH = "m/44'/1237'/0'/0/0";

// BIP32 constants
const MASTER_SECRET_OLD = "Bitcoin seed";

export interface KeyPair {
  privateKey: string;
  publicKey: string;
  nsec: string;
  npub: string;
  seedPhrase?: string;
}

/**
 * Parse a BIP32 path into its components
 * @param path - BIP32 path string (e.g. "m/44'/1237'/0'/0/0")
 * @returns Array of path indices
 */
function parsePath(path: string): number[] {
  if (!path.startsWith('m/')) {
    throw new Error('Invalid path format');
  }
  return path
    .slice(2)
    .split('/')
    .map(part => {
      if (part.endsWith("'")) {
        return parseInt(part.slice(0, -1)) + HARDENED_OFFSET;
      }
      return parseInt(part);
    });
}

/**
 * Derive a private key using BIP32 derivation
 * @param seed - Seed bytes
 * @param path - BIP32 path
 * @returns Derived private key in hex format
 */
function derivePrivateKey(seed: Uint8Array, path: string): string {
  // Generate master key
  const I = hmac.create(sha512, MASTER_SECRET_OLD)
    .update(seed)
    .digest();
  
  let privateKey = I.slice(0, 32);
  let chainCode = I.slice(32);
  
  // Derive through path
  for (const index of parsePath(path)) {
    const data = new Uint8Array(37);
    if (index >= HARDENED_OFFSET) {
      data[0] = 0x00;
      data.set(privateKey, 1);
      data.set(new Uint8Array(4), 33);
      const be = new DataView(data.buffer);
      be.setUint32(33, index);
    } else {
      const pub = getPublicKey(bytesToHex(privateKey));
      data.set(hexToBytes(pub), 0);
      const be = new DataView(data.buffer);
      be.setUint32(33, index);
    }
    
    const I = hmac.create(sha512, chainCode)
      .update(data)
      .digest();
    
    privateKey = I.slice(0, 32);
    chainCode = I.slice(32);
  }
  
  return bytesToHex(privateKey);
}

/**
 * Validate a BIP-39 mnemonic seed phrase
 * @param mnemonic - The mnemonic seed phrase to validate
 * @returns True if the mnemonic is valid, false otherwise
 */
export function validateSeedPhrase(mnemonic: string): boolean {
  try {
    return validateMnemonic(mnemonic);
  } catch {
    return false;
  }
}

/**
 * Generate a new BIP-39 mnemonic seed phrase
 * @param wordCount - The number of words in the mnemonic (12 or 24)
 * @returns The generated mnemonic seed phrase
 * @throws {Error} If word count is invalid
 */
export function generateSeedPhrase(wordCount: number = 12): string {
  if (wordCount !== 12 && wordCount !== 24) {
    throw new Error('Word count must be either 12 or 24');
  }
  const strength = (wordCount / 3) * 32;
  return generateMnemonic(strength);
}

/**
 * Derives a private key from a seed phrase using BIP32/BIP39/BIP44
 * @param seedPhrase - The seed phrase to derive the key from
 * @returns The generated private key in hex format
 * @throws {Error} If seed phrase is invalid or key derivation fails
 */
export async function privateKeyFromSeed(seedPhrase: string): Promise<string> {
  try {
    if (!validateMnemonic(seedPhrase)) {
      throw new Error('Invalid mnemonic');
    }

    // Generate seed from mnemonic
    const seed = mnemonicToSeedSync(seedPhrase);
    
    // Derive master key
    const I = hmac.create(sha512, MASTER_SECRET);
    I.update(seed);
    const IL = I.digest().slice(0, 32);
    const IR = I.digest().slice(32);
    
    // Derive child keys
    let key = IL;
    let chainCode = IR;

    // Parse path
    const path = NOSTR_PATH.split('/');
    if (path[0] === 'm') path.shift();

    // Derive each level
    for (const level of path) {
      let index = parseInt(level.replace("'", ""));
      if (level.includes("'")) index += HARDENED_OFFSET;

      const data = new Uint8Array(37);
      
      // Handle hardened derivation
      if (index >= HARDENED_OFFSET) {
        data[0] = 0x00;
        data.set(key, 1);
        const be = new DataView(data.buffer);
        be.setUint32(33, index);
      } else {
        const pub = getPublicKey(bytesToHex(key));
        data.set(hexToBytes(pub));
        const be = new DataView(data.buffer);
        be.setUint32(33, index);
      }

      const I = hmac.create(sha512, chainCode);
      I.update(data);
      const IL = I.digest().slice(0, 32);
      const IR = I.digest().slice(32);

      // Derive next level
      key = IL;
      chainCode = IR;
    }

    const privateKey = bytesToHex(key);
    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key generated');
    }

    return privateKey;
  } catch (error) {
    throw new Error(`Failed to derive private key: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Generate a new random mnemonic phrase
 */
export function generateSeedPhraseNew(strength: number = 256): string {
  return generateMnemonic(strength);
}

/**
 * Generate a key pair from a seed phrase
 */
export async function seedPhraseToKeyPair(seedPhrase: string): Promise<{ privateKey: string; publicKey: string; nsec: string; npub: string }> {
  try {
    const privateKeyHex = await privateKeyFromSeed(seedPhrase);
    
    if (!validatePrivateKey(privateKeyHex)) {
      throw new Error('Invalid private key');
    }
    
    const publicKey = getPublicKey(privateKeyHex);
    if (!validatePublicKey(publicKey)) {
      throw new Error('Invalid public key generated');
    }
    
    return {
      privateKey: privateKeyHex,
      publicKey,
      nsec: hexToNsec(privateKeyHex),
      npub: hexToNpub(publicKey)
    };
  } catch (error) {
    throw new Error(`Failed to generate key pair: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Convert a BIP39 seed phrase to a Nostr key pair
 * @param seedPhrase - The BIP39 seed phrase to convert
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 */
export function seedPhraseToKeyPairOld(seedPhrase: string): KeyPair {
  const privateKey = privateKeyFromSeedOld(seedPhrase);
  const publicKey = getPublicKey(privateKey);
  
  return {
    privateKey,
    publicKey,
    nsec: hexToNsec(privateKey),
    npub: hexToNpub(publicKey),
    seedPhrase
  };
}

/**
 * Derives a private key from a seed phrase using BIP32/BIP39/BIP44
 * @param seedPhrase - The seed phrase to derive the key from
 * @returns The generated private key in hex format
 * @throws {Error} If seed phrase is invalid or key derivation fails
 */
function privateKeyFromSeedOld(seedPhrase: string): string {
  if (!validateSeedPhrase(seedPhrase)) {
    throw new Error('Invalid seed phrase');
  }

  // Generate seed from mnemonic
  const seed = mnemonicToSeedSync(seedPhrase);
  
  // Derive private key using BIP32
  const privateKey = derivePrivateKey(seed, NOSTR_BIP32_PATH);
  
  // Validate the derived private key
  if (!validatePrivateKey(privateKey)) {
    throw new Error('Invalid private key generated');
  }
  
  return privateKey;
}

/**
 * Generate a new key pair with a random seed phrase
 * @returns A new key pair containing private and public keys in various formats
 */
export function generateKeyPairWithSeed(): KeyPair {
  const seedPhrase = generateSeedPhrase();
  return seedPhraseToKeyPairOld(seedPhrase);
}

/**
 * Create a key pair from a hex private key
 * @param privateKeyHex - The hex-encoded private key
 * @returns A key pair containing private and public keys in various formats
 * @throws {Error} If the private key is invalid
 */
export function keyPairFromPrivateKey(privateKeyHex: string): KeyPair {
  if (!validatePrivateKey(privateKeyHex)) {
    throw new Error('Invalid private key');
  }
  
  const publicKey = getPublicKey(privateKeyHex);
  if (!validatePublicKey(publicKey)) {
    throw new Error('Invalid public key generated');
  }
  
  return {
    privateKey: privateKeyHex,
    publicKey,
    nsec: hexToNsec(privateKeyHex),
    npub: hexToNpub(publicKey)
  };
}