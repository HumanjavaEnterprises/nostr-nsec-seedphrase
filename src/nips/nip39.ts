import { Buffer } from 'buffer';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { wordlist } from '@scure/bip39/wordlists/english';
import { 
  seedWordsToPrivateKey, 
  formatSeedPhrase, 
  parseSeedPhrase,
  encryptSeedPhrase as encryptSeed,
  decryptSeedPhrase as decryptSeed,
  validateSeedWords
} from '../crypto/seed';

export class Nip39Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Nip39Error';
  }
}

/**
 * Metadata interface for NIP-39 seed phrase generation
 */
export interface Nip39Metadata {
  /** The name of the user */
  name: string;
  /** Optional email address */
  email?: string;
  /** Optional birthdate in YYYY-MM-DD format */
  birthdate?: string;
  /** Optional about/bio text */
  about?: string;
  /** Optional URL to profile picture */
  picture?: string;
}

/**
 * Generates seed words from user metadata
 * @param metadata User metadata to generate seed words from
 * @returns Space-separated seed words string
 */
export function generateSeedWords(metadata: Nip39Metadata): string {
  if (!metadata || !metadata.name) {
    throw new Nip39Error('Name is required in metadata');
  }

  // Convert metadata to JSON string, ensuring consistent ordering
  const orderedMetadata = {
    name: metadata.name,
    email: metadata.email || '',
    birthdate: metadata.birthdate || '',
    about: metadata.about || '',
    picture: metadata.picture || ''
  };
  
  // Create hash of metadata
  const metadataString = JSON.stringify(orderedMetadata);
  const hash = sha256(Buffer.from(metadataString));
  const hashHex = bytesToHex(hash);
  
  // Convert hash to words (12 words = 128 bits)
  const words: string[] = [];
  for (let i = 0; i < 12; i++) {
    const index = parseInt(hashHex.slice(i * 4, (i + 1) * 4), 16) % wordlist.length;
    words.push(wordlist[index]);
  }
  
  return words.join(' ');
}

/**
 * Encrypt a seed phrase with a password
 * @param seedPhrase The seed phrase to encrypt
 * @param password The password to encrypt with
 * @returns Encrypted seed phrase
 */
export async function encryptSeedPhrase(seedPhrase: string, password: string): Promise<string> {
  if (!seedPhrase || !seedPhrase.trim()) {
    throw new Nip39Error('Seed phrase cannot be empty');
  }
  if (!password || !password.trim()) {
    throw new Nip39Error('Password cannot be empty');
  }

  try {
    return await encryptSeed(seedPhrase, password);
  } catch (error) {
    throw new Nip39Error(`Failed to encrypt seed phrase: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Decrypt an encrypted seed phrase with a password
 * @param encryptedSeedPhrase The encrypted seed phrase
 * @param password The password to decrypt with
 * @returns Decrypted seed phrase
 */
export async function decryptSeedPhrase(encryptedSeedPhrase: string, password: string): Promise<string> {
  if (!encryptedSeedPhrase || !encryptedSeedPhrase.trim()) {
    throw new Nip39Error('Encrypted seed phrase cannot be empty');
  }
  if (!password || !password.trim()) {
    throw new Nip39Error('Password cannot be empty');
  }

  try {
    return await decryptSeed(encryptedSeedPhrase, password);
  } catch (error) {
    throw new Nip39Error(`Failed to decrypt seed phrase: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

// Re-export seed phrase functions with underscore prefix to indicate internal use
export {
  seedWordsToPrivateKey as _seedWordsToPrivateKey,
  formatSeedPhrase as _formatSeedPhrase,
  parseSeedPhrase as _parseSeedPhrase,
  validateSeedWords
};
