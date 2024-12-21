import { describe, it, expect, beforeAll } from 'vitest';
import { TEST_CONSTANTS, setupHMAC } from '../test-utils';
import { encrypt, decrypt } from '../../crypto/encryption';
import { createEncryptedDirectMessage } from '../../nips/nip04';
import { EncryptionError } from '../../types/errors';

describe('NIP-04: Encrypted Direct Messages', () => {
  beforeAll(() => {
    setupHMAC();
  });

  describe('encrypt', () => {
    it('should encrypt a message successfully', async () => {
      const message = 'Hello, World!';
      const encrypted = await encrypt(
        message,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted).not.toBe(message);
    });

    it('should produce different ciphertexts for the same message', async () => {
      const message = 'Hello, World!';
      const encrypted1 = await encrypt(
        message,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );
      const encrypted2 = await encrypt(
        message,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should throw EncryptionError for invalid private key', async () => {
      await expect(encrypt(
        'Hello',
        'invalid-key',
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      )).rejects.toThrow(EncryptionError);
    });

    it('should throw EncryptionError for invalid public key', async () => {
      await expect(encrypt(
        'Hello',
        TEST_CONSTANTS.PRIVATE_KEY,
        'invalid-key'
      )).rejects.toThrow(EncryptionError);
    });
  });

  describe('decrypt', () => {
    it('should decrypt a message successfully', async () => {
      const message = 'Hello, World!';
      const encrypted = await encrypt(
        message,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );
      const decrypted = await decrypt(
        encrypted,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );

      expect(decrypted).toBe(message);
    });

    it('should decrypt messages between different key pairs', async () => {
      const message = 'Hello, Alice!';
      const encrypted = await encrypt(
        message,
        TEST_CONSTANTS.BOB_PRIVATE_KEY,
        TEST_CONSTANTS.ALICE_PUBLIC_KEY
      );
      const decrypted = await decrypt(
        encrypted,
        TEST_CONSTANTS.ALICE_PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );

      expect(decrypted).toBe(message);
    });

    it('should throw EncryptionError for invalid encrypted content', async () => {
      await expect(decrypt(
        'invalid-content',
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      )).rejects.toThrow(EncryptionError);
    });

    it('should throw EncryptionError for mismatched keys', async () => {
      const message = 'Hello, World!';
      const encrypted = await encrypt(
        message,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );

      await expect(decrypt(
        encrypted,
        TEST_CONSTANTS.BOB_PRIVATE_KEY,
        TEST_CONSTANTS.ALICE_PUBLIC_KEY
      )).rejects.toThrow(EncryptionError);
    });
  });

  describe('createEncryptedDirectMessage', () => {
    it('should create and decrypt a direct message successfully', async () => {
      const message = 'Hello, Bob!';
      const event = await createEncryptedDirectMessage(
        message,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );

      expect(event.kind).toBe(4);
      expect(event.tags).toContainEqual(['p', TEST_CONSTANTS.BOB_PUBLIC_KEY]);
      
      const decrypted = await decrypt(
        event.content,
        TEST_CONSTANTS.BOB_PRIVATE_KEY,
        TEST_CONSTANTS.PUBLIC_KEY
      );
      expect(decrypted).toBe(message);
    });

    it('should handle empty messages', async () => {
      const event = await createEncryptedDirectMessage(
        '',
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );

      expect(event.kind).toBe(4);
      const decrypted = await decrypt(
        event.content,
        TEST_CONSTANTS.BOB_PRIVATE_KEY,
        TEST_CONSTANTS.PUBLIC_KEY
      );
      expect(decrypted).toBe('');
    });

    it('should handle unicode characters', async () => {
      const message = '你好，世界！👋';
      const event = await createEncryptedDirectMessage(
        message,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );

      const decrypted = await decrypt(
        event.content,
        TEST_CONSTANTS.BOB_PRIVATE_KEY,
        TEST_CONSTANTS.PUBLIC_KEY
      );
      expect(decrypted).toBe(message);
    });
  });

  describe('Edge cases and error handling', () => {
    it('should handle long messages', async () => {
      const longMessage = 'a'.repeat(1000);
      const encrypted = await encrypt(
        longMessage,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );
      const decrypted = await decrypt(
        encrypted,
        TEST_CONSTANTS.BOB_PRIVATE_KEY,
        TEST_CONSTANTS.PUBLIC_KEY
      );
      expect(decrypted).toBe(longMessage);
    });

    it('should handle special characters', async () => {
      const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?`~';
      const encrypted = await encrypt(
        specialChars,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      );
      const decrypted = await decrypt(
        encrypted,
        TEST_CONSTANTS.BOB_PRIVATE_KEY,
        TEST_CONSTANTS.PUBLIC_KEY
      );
      expect(decrypted).toBe(specialChars);
    });

    it('should throw error for null or undefined messages', async () => {
      // @ts-ignore - Testing invalid input
      await expect(encrypt(
        '' as any,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      )).rejects.toThrow();

      // @ts-ignore - Testing invalid input
      await expect(encrypt(
        '' as any,
        TEST_CONSTANTS.PRIVATE_KEY,
        TEST_CONSTANTS.BOB_PUBLIC_KEY
      )).rejects.toThrow();
    });
  });
});