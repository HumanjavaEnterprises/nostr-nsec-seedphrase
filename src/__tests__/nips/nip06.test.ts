import { describe, it, expect, beforeAll } from 'vitest';
import { mockSecp256k1, mockBech32, mockBip39, TEST_CONSTANTS } from '../test-utils';
import {
  generateSeedPhrase,
  validateSeedPhrase,
  privateKeyFromSeed,
  derivePrivateKey
} from '../../nips/nip06';
import { hexToBytes } from '@noble/hashes/utils';

// Setup mocks
mockSecp256k1();
mockBech32();
mockBip39();

describe('NIP-06: Key Derivation from Mnemonic Seed Phrase', () => {
  describe('Seed Phrase Generation', () => {
    it('should generate valid seed phrases', () => {
      const seedPhrase = generateSeedPhrase();
      expect(seedPhrase).toBeDefined();
      expect(typeof seedPhrase).toBe('string');
      expect(seedPhrase.split(' ').length).toBe(12);
    });

    it('should validate correct seed phrases', () => {
      const isValid = validateSeedPhrase(TEST_CONSTANTS.SEED_PHRASE);
      expect(isValid).toBe(true);
    });

    it('should reject invalid seed phrases', () => {
      const invalidPhrases = [
        'test', // too short
        'test test test', // not enough words
        'test '.repeat(13), // too many words
        '', // empty
        '12345 67890 test', // invalid words
      ];

      invalidPhrases.forEach(phrase => {
        const isValid = validateSeedPhrase(phrase);
        expect(isValid).toBe(false);
      });
    });
  });

  describe('Private Key Generation', () => {
    it('should generate private keys from seed phrases', async () => {
      const privateKey = privateKeyFromSeed(TEST_CONSTANTS.SEED_PHRASE);
      expect(privateKey).toBeDefined();
      expect(typeof privateKey).toBe('string');
      expect((await privateKey).length).toBe(64); // 32 bytes in hex
    });

    it('should generate consistent private keys for the same seed phrase', () => {
      const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      const key1 = privateKeyFromSeed(testMnemonic);
      const key2 = privateKeyFromSeed(testMnemonic);
      expect(key1).toBe(key2);
    });

    it('should throw error for invalid seed phrases', () => {
      expect(() => privateKeyFromSeed('invalid seed phrase')).toThrow();
    });
  });

  describe('Private Key from Entropy', () => {
    it('should generate private keys from entropy', () => {
      const entropy = new Uint8Array([1, 2, 3, 4]);
      const entropyHex = Buffer.from(entropy).toString('hex');
      const privateKey = derivePrivateKey(hexToBytes(entropyHex));
      expect(privateKey).toBeDefined();
      expect(typeof privateKey).toBe('string');
      expect(privateKey.length).toBe(64); // 32 bytes in hex
    });

    it('should generate consistent private keys for the same entropy', () => {
      const entropy = new Uint8Array([1, 2, 3, 4]);
      const entropyHex = Buffer.from(entropy).toString('hex');
      const key1 = derivePrivateKey(hexToBytes(entropyHex));
      const key2 = derivePrivateKey(hexToBytes(entropyHex));
      expect(key1).toBe(key2);
    });
  });
});
