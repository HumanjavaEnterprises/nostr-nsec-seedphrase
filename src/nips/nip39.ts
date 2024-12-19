import { Buffer } from 'buffer';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { wordlist } from '@scure/bip39/wordlists/english';
import { 
  validateSeedWords, 
  seedWordsToPrivateKey, 
  formatSeedPhrase, 
  parseSeedPhrase,
  encryptSeedPhrase,
  decryptSeedPhrase
} from '../crypto/seed';

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
  
  return formatSeedPhrase(words);
}

// Re-export seed phrase functions
export { 
  validateSeedWords, 
  seedWordsToPrivateKey,
  formatSeedPhrase,
  parseSeedPhrase,
  encryptSeedPhrase,
  decryptSeedPhrase
} from '../crypto/seed';
