import { describe, it, expect, beforeAll } from 'vitest';
import { TEST_CONSTANTS, setupHMAC } from '../test-utils';
import { 
  encryptPrivateKey,
  decryptPrivateKey,
  validateEncryptedPrivateKey,
  generateLogParams,
  ScryptParams,
  DEFAULT_SCRYPT_PARAMS
} from '../../nips/nip49';

describe('NIP-49: Private Key Encryption', () => {
  beforeAll(() => {
    setupHMAC();
  });

  const testPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const testPassword = 'test-password';

  describe('Encryption Parameters', () => {
    it('generateLogParams returns valid parameters', () => {
      const params = generateLogParams();
      
      expect(params.N).toBe(DEFAULT_SCRYPT_PARAMS.N);
      expect(params.r).toBe(DEFAULT_SCRYPT_PARAMS.r);
      expect(params.p).toBe(DEFAULT_SCRYPT_PARAMS.p);
      expect(params.dkLen).toBe(DEFAULT_SCRYPT_PARAMS.dkLen);
    });
  });

  describe('Private Key Encryption', () => {
    it('encryptPrivateKey encrypts key correctly', async () => {
      const encrypted = await encryptPrivateKey(testPrivateKey, testPassword);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it('decryptPrivateKey decrypts key correctly', async () => {
      const encrypted = await encryptPrivateKey(testPrivateKey, testPassword);
      const decrypted = await decryptPrivateKey(encrypted, testPassword);
      expect(decrypted).toBe(testPrivateKey);
    });

    it('validateEncryptedPrivateKey validates correctly', async () => {
      const encrypted = await encryptPrivateKey(testPrivateKey, testPassword);
      const isValid = await validateEncryptedPrivateKey(encrypted, testPassword);
      expect(isValid).toBe(true);
    });

    it('validateEncryptedPrivateKey fails on invalid key', async () => {
      const isValid = await validateEncryptedPrivateKey('invalid-key', testPassword);
      expect(isValid).toBe(false);
    });
  });

  describe('Error Handling', () => {
    it('encryption fails with invalid parameters', async () => {
      const invalidParams: ScryptParams = {
        N: 1024, // Too small
        r: 8,
        p: 1,
        dkLen: 32
      };

      await expect(
        encryptPrivateKey(testPrivateKey, testPassword, invalidParams)
      ).rejects.toThrow();
    });

    it('decryption fails with wrong password', async () => {
      const encrypted = await encryptPrivateKey(testPrivateKey, testPassword);
      await expect(
        decryptPrivateKey(encrypted, 'wrong-password')
      ).rejects.toThrow();
    });
  });

  describe('Default Parameters', () => {
    it('encryption uses default parameters when not provided', async () => {
      const encrypted = await encryptPrivateKey(testPrivateKey, testPassword);
      const decrypted = await decryptPrivateKey(encrypted, testPassword);
      expect(decrypted).toBe(testPrivateKey);
    });
  });
});
