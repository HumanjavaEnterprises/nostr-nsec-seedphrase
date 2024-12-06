import { getPublicKey, nip19 } from 'nostr-tools';
import * as secp256k1 from '@noble/secp256k1';
import * as bip39 from 'bip39';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export interface KeyPair {
  privateKey: string;
  publicKey: string;
  nsec: string;
  npub: string;
}

export interface KeyPairWithSeed extends KeyPair {
  seedPhrase: string;
}

/**
 * Generate a new seed phrase
 */
export function generateSeedPhrase(): string {
  const entropy = secp256k1.utils.randomPrivateKey();
  return bip39.entropyToMnemonic(bytesToHex(entropy));
}

/**
 * Convert a seed phrase to a private key
 */
export function seedPhraseToPrivateKey(seedPhrase: string): string {
  if (!validateSeedPhrase(seedPhrase)) {
    throw new Error('Invalid seed phrase');
  }
  const entropy = bip39.mnemonicToEntropy(seedPhrase);
  return entropy;
}

/**
 * Validate a seed phrase
 */
export function validateSeedPhrase(seedPhrase: string): boolean {
  return bip39.validateMnemonic(seedPhrase);
}

/**
 * Convert a seed phrase to a key pair
 */
export function seedPhraseToKeyPair(seedPhrase: string): KeyPair {
  const privateKey = seedPhraseToPrivateKey(seedPhrase);
  const publicKey = getPublicKey(hexToBytes(privateKey));
  const nsec = nip19.nsecEncode(hexToBytes(privateKey));
  const npub = nip19.npubEncode(hexToBytes(publicKey));
  
  return {
    privateKey,
    publicKey,
    nsec,
    npub
  };
}

/**
 * Generate a new Nostr key pair with corresponding seed phrase
 */
export function generateNew(): KeyPairWithSeed {
  try {
    // Generate a new private key
    const privateKeyBytes = secp256k1.utils.randomPrivateKey();
    const privateKeyHex = bytesToHex(privateKeyBytes);
    
    // Convert to nsec
    const nsec = nip19.nsecEncode(privateKeyBytes);
    
    // Generate public key
    const publicKeyHex = getPublicKey(privateKeyBytes);
    const npub = nip19.npubEncode(publicKeyHex);
    
    // Convert private key to seed phrase
    const seedPhrase = bip39.entropyToMnemonic(privateKeyHex);

    return {
      privateKey: privateKeyHex,
      publicKey: publicKeyHex,
      nsec,
      npub,
      seedPhrase
    };
  } catch (error) {
    throw new Error(`Failed to generate new key pair: ${(error as Error).message}`);
  }
}

/**
 * Create a key pair from a hex private key
 */
export function fromHex(privateKeyHex: string): KeyPair {
  try {
    // Validate hex format
    if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error('Invalid hex private key format. Must be 64 characters of hex.');
    }

    const nsec = nip19.nsecEncode(hexToBytes(privateKeyHex));
    const publicKeyHex = getPublicKey(hexToBytes(privateKeyHex));
    const npub = nip19.npubEncode(hexToBytes(publicKeyHex));

    return {
      privateKey: privateKeyHex,
      publicKey: publicKeyHex,
      nsec,
      npub
    };
  } catch (error) {
    throw new Error(`Failed to create key pair from hex: ${(error as Error).message}`);
  }
}

/**
 * Convert an nsec to its hex representation
 */
export function nsecToHex(nsec: string): string {
  try {
    const { type, data } = nip19.decode(nsec);
    if (type !== 'nsec') {
      throw new Error('Invalid nsec format');
    }
    return bytesToHex(data as Uint8Array);
  } catch (error) {
    throw new Error(`Failed to convert nsec to hex: ${(error as Error).message}`);
  }
}

/**
 * Convert an npub to its hex representation
 */
export function npubToHex(npub: string): string {
  try {
    const { type, data } = nip19.decode(npub);
    if (type !== 'npub') {
      throw new Error('Invalid npub format');
    }
    return data as string;
  } catch (error) {
    throw new Error(`Failed to convert npub to hex: ${(error as Error).message}`);
  }
}

/**
 * Convert a hex public key to npub format
 */
export function hexToNpub(publicKeyHex: string): string {
  try {
    return nip19.npubEncode(publicKeyHex);
  } catch (error) {
    throw new Error(`Failed to convert hex to npub: ${(error as Error).message}`);
  }
}

/**
 * Convert a hex private key to nsec format
 */
export function hexToNsec(privateKeyHex: string): string {
  try {
    return nip19.nsecEncode(hexToBytes(privateKeyHex));
  } catch (error) {
    throw new Error(`Failed to convert hex to nsec: ${(error as Error).message}`);
  }
}
