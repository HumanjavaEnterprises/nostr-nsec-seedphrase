import { getPublicKey, nip19 } from 'nostr-tools';
import * as secp256k1 from '@noble/secp256k1';
import * as bip39 from 'bip39';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export interface KeyPair {
  nsec: string;
  npub: string;
  privateKeyHex: string;
  publicKeyHex: string;
}

export interface KeyPairWithSeed extends KeyPair {
  seedPhrase: string;
}

export class NostrSeedPhrase {
  /**
   * Convert a Nostr nsec private key to a BIP39 seed phrase
   * @param nsec - The nsec private key to convert
   * @returns Object containing the seed phrase and original nsec
   */
  static nsecToSeed(nsec: string): { seedPhrase: string } {
    try {
      const { type, data } = nip19.decode(nsec);
      if (type !== 'nsec') {
        throw new Error('Invalid nsec format');
      }

      // Convert the hex private key to bytes and back to hex for bip39
      const privateKeyHex = bytesToHex(data as Uint8Array);
      
      // Generate mnemonic from the private key bytes
      const seedPhrase = bip39.entropyToMnemonic(privateKeyHex);

      return {
        seedPhrase
      };
    } catch (error) {
      throw new Error(`Failed to convert nsec to seed phrase: ${(error as Error).message}`);
    }
  }

  /**
   * Convert a BIP39 seed phrase to a Nostr nsec private key
   * @param seedPhrase - The BIP39 mnemonic seed phrase
   * @returns Object containing the nsec private key and original seed phrase
   */
  static seedToNsec(seedPhrase: string): KeyPair {
    try {
      if (!NostrSeedPhrase.validateSeedPhrase(seedPhrase)) {
        throw new Error('Invalid mnemonic phrase');
      }

      // Convert mnemonic to entropy (private key hex)
      const privateKeyHex = bip39.mnemonicToEntropy(seedPhrase);
      
      // Generate nsec
      const nsec = nip19.nsecEncode(hexToBytes(privateKeyHex));
      
      // Generate public key
      const publicKeyHex = getPublicKey(hexToBytes(privateKeyHex));
      const npub = nip19.npubEncode(publicKeyHex);

      return {
        nsec,
        npub,
        privateKeyHex,
        publicKeyHex
      };
    } catch (error) {
      throw new Error(`Failed to convert seed phrase to nsec: ${(error as Error).message}`);
    }
  }

  /**
   * Validate a BIP39 seed phrase
   * @param seedPhrase - The seed phrase to validate
   * @returns boolean indicating if the seed phrase is valid
   */
  static validateSeedPhrase(seedPhrase: string): boolean {
    return bip39.validateMnemonic(seedPhrase);
  }

  /**
   * Generate a new Nostr key pair with corresponding seed phrase
   * @returns Object containing the new nsec private key, npub public key, and seed phrase
   */
  static generateNew(): KeyPairWithSeed {
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
        nsec,
        npub,
        seedPhrase,
        privateKeyHex,
        publicKeyHex
      };
    } catch (error) {
      throw new Error(`Failed to generate new key pair: ${(error as Error).message}`);
    }
  }

  /**
   * Create a key pair from a hex private key
   * @param privateKeyHex - The hex private key to convert
   * @returns Object containing the nsec, npub, and hex versions of the keys
   */
  static fromHex(privateKeyHex: string): KeyPair {
    try {
      // Validate hex format
      if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
        throw new Error('Invalid hex private key format. Must be 64 characters of hex.');
      }

      const nsec = nip19.nsecEncode(hexToBytes(privateKeyHex));
      const publicKeyHex = getPublicKey(hexToBytes(privateKeyHex));
      const npub = nip19.npubEncode(publicKeyHex);

      return {
        nsec,
        npub,
        privateKeyHex,
        publicKeyHex
      };
    } catch (error) {
      throw new Error(`Failed to create key pair from hex: ${(error as Error).message}`);
    }
  }

  /**
   * Convert an nsec to its hex representation
   * @param nsec - The nsec to convert
   * @returns The hex private key
   */
  static nsecToHex(nsec: string): string {
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
   * @param npub - The npub to convert
   * @returns The hex public key
   */
  static npubToHex(npub: string): string {
    try {
      const { type, data } = nip19.decode(npub);
      if (type !== 'npub') {
        throw new Error('Invalid npub format');
      }
      return bytesToHex(data as Uint8Array);
    } catch (error) {
      throw new Error(`Failed to convert npub to hex: ${(error as Error).message}`);
    }
  }

  /**
   * Convert a hex public key to npub format
   * @param publicKeyHex - The hex public key to convert
   * @returns The npub
   */
  static hexToNpub(publicKeyHex: string): string {
    try {
      return nip19.npubEncode(publicKeyHex);
    } catch (error) {
      throw new Error(`Failed to convert hex to npub: ${(error as Error).message}`);
    }
  }

  /**
   * Convert a hex private key to nsec format
   * @param privateKeyHex - The hex private key to convert
   * @returns The nsec
   */
  static hexToNsec(privateKeyHex: string): string {
    try {
      return nip19.nsecEncode(hexToBytes(privateKeyHex));
    } catch (error) {
      throw new Error(`Failed to convert hex to nsec: ${(error as Error).message}`);
    }
  }
}
