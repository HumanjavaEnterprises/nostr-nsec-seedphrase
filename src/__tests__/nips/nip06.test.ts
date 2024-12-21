import { describe, it, expect } from 'vitest';
import {
  generateSeedPhrase,
  privateKeyFromSeed,
  seedPhraseToKeyPair,
} from '../../nips/nip06';
import { validatePrivateKey } from '../../crypto/keys';
import { TEST_CONSTANTS } from '../test-utils';

describe('NIP-06: Key Derivation from Mnemonic Seed Phrase', () => {
  describe('Seed Phrase Generation', () => {
    it('should generate valid seed phrases', () => {
      const seedPhrase = generateSeedPhrase();
      expect(seedPhrase.split(' ').length).toBe(24); // Default is 24 words
    });

    it('should generate different seed phrases each time', () => {
      const phrase1 = generateSeedPhrase();
      const phrase2 = generateSeedPhrase();
      expect(phrase1).not.toBe(phrase2);
    });
  });

  describe('Private Key Generation', () => {
    const testMnemonic = TEST_CONSTANTS.TEST_MNEMONIC;

    it('should generate private keys from seed phrases', async () => {
      const privateKey = await privateKeyFromSeed(testMnemonic);
      expect(privateKey).toBeDefined();
      expect(typeof privateKey).toBe('string');
      expect(privateKey.length).toBe(64); // 32 bytes in hex
      expect(validatePrivateKey(privateKey)).toBe(true);
    });

    it('should generate consistent private keys for the same seed phrase', async () => {
      const key1 = await privateKeyFromSeed(testMnemonic);
      const key2 = await privateKeyFromSeed(testMnemonic);
      expect(key1).toBe(key2);
    });

    it('should reject invalid seed phrases', async () => {
      await expect(privateKeyFromSeed('invalid seed phrase')).rejects.toThrow();
    });
  });

  describe('Key Pair Generation', () => {
    const testMnemonic = TEST_CONSTANTS.TEST_MNEMONIC;

    it('should generate valid key pairs from seed phrase', async () => {
      const keyPair = await seedPhraseToKeyPair(testMnemonic);
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.nsec).toBeDefined();
      expect(keyPair.npub).toBeDefined();
    });

    it('should generate consistent key pairs for the same seed phrase', async () => {
      const pair1 = await seedPhraseToKeyPair(testMnemonic);
      const pair2 = await seedPhraseToKeyPair(testMnemonic);
      expect(pair1.privateKey).toBe(pair2.privateKey);
      expect(pair1.publicKey).toBe(pair2.publicKey);
      expect(pair1.nsec).toBe(pair2.nsec);
      expect(pair1.npub).toBe(pair2.npub);
    });
  });
});
