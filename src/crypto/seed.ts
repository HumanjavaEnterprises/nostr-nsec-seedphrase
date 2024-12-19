import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { wordlist } from '@scure/bip39/wordlists/english';

// Utility function to convert hex string to bytes
function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

export class SeedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SeedError';
  }
}

/**
 * Validates a list of seed words
 * @param words Array of seed words to validate
 * @returns true if all words are valid BIP39 words
 */
export function validateSeedWords(words: string[]): boolean {
  return words.every(word => wordlist.includes(word.toLowerCase()));
}

/**
 * Converts seed words to a private key
 * @param words Array of seed words
 * @returns Hex-encoded private key
 * @throws SeedError if seed words are invalid
 */
export function seedWordsToPrivateKey(words: string[]): string {
  if (!validateSeedWords(words)) {
    throw new SeedError('Invalid seed words');
  }

  // Join words and hash to create private key
  const seedPhrase = words.join(' ').toLowerCase();
  const privateKey = sha256(Buffer.from(seedPhrase, 'utf8'));
  return bytesToHex(privateKey);
}

/**
 * Formats seed words into a readable string
 * @param words Array of seed words
 * @returns Space-separated string of words
 */
export function formatSeedPhrase(words: string[]): string {
  return words.join(' ').toLowerCase();
}

/**
 * Parses a seed phrase string into an array of words
 * @param phrase Space-separated seed phrase
 * @returns Array of seed words
 */
export function parseSeedPhrase(phrase: string): string[] {
  return phrase.trim().toLowerCase().split(/\s+/);
}

/**
 * Encrypts a seed phrase with a password
 * @param seedPhrase The seed phrase to encrypt
 * @param password The password to encrypt with
 * @returns Encrypted seed phrase as a hex string
 */
export async function encryptSeedPhrase(seedPhrase: string, password: string): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const phraseBytes = encoder.encode(seedPhrase);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Derive key from password
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    
    const derivedKey = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      key,
      256
    );
    
    // Encrypt using AES-GCM
    const encryptKey = await crypto.subtle.importKey(
      'raw',
      derivedKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      encryptKey,
      phraseBytes
    );
    
    // Combine salt + iv + ciphertext
    const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encrypted), salt.length + iv.length);
    
    return bytesToHex(result);
  } catch (error) {
    throw new SeedError(`Failed to encrypt seed phrase: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Decrypts an encrypted seed phrase with a password
 * @param encryptedPhrase The encrypted seed phrase (hex string)
 * @param password The password to decrypt with
 * @returns Decrypted seed phrase
 */
export async function decryptSeedPhrase(encryptedPhrase: string, password: string): Promise<string> {
  try {
    const data = new Uint8Array(fromHex(encryptedPhrase));
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ciphertext = data.slice(28);
    
    const encoder = new TextEncoder();
    
    // Derive key from password
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    
    const derivedKey = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      key,
      256
    );
    
    // Decrypt using AES-GCM
    const decryptKey = await crypto.subtle.importKey(
      'raw',
      derivedKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv
      },
      decryptKey,
      ciphertext
    );
    
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    throw new SeedError(`Failed to decrypt seed phrase: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}
