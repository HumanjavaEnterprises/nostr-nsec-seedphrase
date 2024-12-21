import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { wordlist } from '@scure/bip39/wordlists/english';

// Polyfill for crypto in Node.js environment
const getCrypto = async () => {
  if (typeof crypto !== 'undefined') {
    return crypto;
  }
  // Node.js environment
  return import('crypto').then((crypto) => crypto.webcrypto);
};

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
 * @returns true if all words are valid BIP39 words and length is correct
 */
export function validateSeedWords(words: string[]): boolean {
  // Check if input is valid array with exactly 12 words
  if (!Array.isArray(words) || words.length !== 12) {
    return false;
  }

  // Check if all words are non-empty strings and in the wordlist
  return words.every(word => 
    typeof word === 'string' && 
    word.length > 0 && 
    wordlist.includes(word.toLowerCase())
  );
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
 * Generates a 16-byte random salt
 */
async function generateSalt(): Promise<Uint8Array> {
  const cryptoObj = await getCrypto() as Crypto;
  const arr = new Uint8Array(16);
  cryptoObj.getRandomValues(arr);
  return arr;
}

/**
 * Generates a 12-byte random initialization vector
 */
async function generateIV(): Promise<Uint8Array> {
  const cryptoObj = await getCrypto() as Crypto;
  const arr = new Uint8Array(12);
  cryptoObj.getRandomValues(arr);
  return arr;
}

/**
 * Encrypts a seed phrase with a password
 * @param seedPhrase The seed phrase to encrypt
 * @param password The password to encrypt with
 * @returns Encrypted seed phrase as a hex string
 */
export async function encryptSeedPhrase(seedPhrase: string, password: string): Promise<string> {
  try {
    const salt = await generateSalt();
    const iv = await generateIV();
    const cryptoObj = await getCrypto();

    // Derive key using PBKDF2
    const encoder = new TextEncoder();
    const keyMaterial = await cryptoObj.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const key = await cryptoObj.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    // Encrypt the seed phrase
    const ciphertext = await cryptoObj.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      key,
      encoder.encode(seedPhrase)
    );

    // Combine salt, iv, and ciphertext
    const result = new Uint8Array(salt.length + iv.length + new Uint8Array(ciphertext).length);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(ciphertext), salt.length + iv.length);

    return bytesToHex(result);
  } catch (error) {
    throw new SeedError(`Failed to encrypt seed phrase: ${error instanceof Error ? error.message : 'Unknown error'}`);
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
    const cryptoObj = await getCrypto();
    const data = fromHex(encryptedPhrase);
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ciphertext = data.slice(28);

    // Derive key using PBKDF2
    const encoder = new TextEncoder();
    const keyMaterial = await cryptoObj.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const key = await cryptoObj.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Decrypt the seed phrase
    const decrypted = await cryptoObj.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv
      },
      key,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    throw new SeedError(`Failed to decrypt seed phrase: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}
