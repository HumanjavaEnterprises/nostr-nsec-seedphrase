import { describe, it, expect, beforeAll } from 'vitest';
import { TEST_CONSTANTS, setupHMAC } from '../test-utils';
import {
  generateSeedWords,
  validateSeedWords,
  encryptSeedPhrase,
  decryptSeedPhrase
} from '../../nips/nip39';

describe('NIP-39: Seed Words and Encryption', () => {
  beforeAll(() => {
    setupHMAC();
  });

  describe('Seed Words Generation', () => {
    it('should generate valid seed words', () => {
      const metadata = { name: 'Test User' };
      const seedWords = generateSeedWords(metadata);
      expect(seedWords).toBeDefined();
      expect(seedWords.split(' ')).toHaveLength(12);
    });

    it('should validate correct seed words', () => {
      const metadata = { name: 'Test User' };
      const seedWords = generateSeedWords(metadata);
      const wordArray = seedWords.split(' ');
      const isValid = validateSeedWords(wordArray);
      expect(isValid).toBe(true);
    });

    it('should reject invalid seed words', () => {
      const invalidInputs = [
        [],
        ['test'],
        ['too', 'short'],
        Array(13).fill('test'),
        ['not', 'valid', 'words', 'in', 'this', 'phrase']
      ];

      invalidInputs.forEach(input => {
        expect(validateSeedWords(input)).toBe(false);
      });
    });
  });

  describe('Seed Phrase Encryption', () => {
    const testPassword = 'test-password';

    it('should encrypt and decrypt seed phrase', async () => {
      const seedPhrase = TEST_CONSTANTS.SEED_PHRASE.split(' ');
      const encrypted = await encryptSeedPhrase(seedPhrase.join(' '), testPassword);
      
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');

      const decrypted = await decryptSeedPhrase(encrypted, testPassword);
      expect(decrypted).toEqual(seedPhrase.join(' '));
    });

    it('should reject invalid password', async () => {
      const seedPhrase = TEST_CONSTANTS.SEED_PHRASE.split(' ');
      const encrypted = await encryptSeedPhrase(seedPhrase.join(' '), testPassword);

      await expect(decryptSeedPhrase(encrypted, 'wrong-password'))
        .rejects.toThrow();
    });

    it('should reject invalid encrypted data', async () => {
      await expect(decryptSeedPhrase('invalid-data', testPassword))
        .rejects.toThrow();
    });
  });
});
