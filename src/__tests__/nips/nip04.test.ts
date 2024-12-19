import { describe, it, expect } from 'vitest';
import { encrypt, decrypt, createEncryptedDirectMessage, EncryptionError } from '../../nips/nip04';

describe('NIP-04: Encrypted Direct Messages', () => {
  // Test keys from the Nostr spec examples
  const alicePrivateKey = '7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a';
  const alicePublicKey = '2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5c12';
  
  const bobPrivateKey = '1f5fe13fa71b6282b1aad34fe440e0d167a56f694c09b6c8262f1d3e0f1f53d5';
  const bobPublicKey = '8e0d180c2c0ba9a81af75e91dfcb337d784d3675785a1c7dd82f00e8b8cc7e82';

  const testMessage = 'Hello, this is a secret message!';

  describe('encrypt', () => {
    it('should encrypt a message successfully', async () => {
      const encrypted = await encrypt(testMessage, alicePrivateKey, bobPublicKey);
      expect(encrypted).toBeTruthy();
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it('should produce different ciphertexts for the same message', async () => {
      const encrypted1 = await encrypt(testMessage, alicePrivateKey, bobPublicKey);
      const encrypted2 = await encrypt(testMessage, alicePrivateKey, bobPublicKey);
      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should throw EncryptionError for invalid private key', async () => {
      await expect(() =>
        encrypt(testMessage, 'invalid-key', bobPublicKey)
      ).rejects.toThrow(EncryptionError);
    });

    it('should throw EncryptionError for invalid public key', async () => {
      await expect(() =>
        encrypt(testMessage, alicePrivateKey, 'invalid-key')
      ).rejects.toThrow(EncryptionError);
    });
  });

  describe('decrypt', () => {
    it('should decrypt a message successfully', async () => {
      const encrypted = await encrypt(testMessage, alicePrivateKey, bobPublicKey);
      const decrypted = await decrypt(encrypted, bobPrivateKey, alicePublicKey);
      expect(decrypted).toBe(testMessage);
    });

    it('should decrypt messages between different key pairs', async () => {
      const encrypted = await encrypt(testMessage, bobPrivateKey, alicePublicKey);
      const decrypted = await decrypt(encrypted, alicePrivateKey, bobPublicKey);
      expect(decrypted).toBe(testMessage);
    });

    it('should throw EncryptionError for invalid encrypted content', async () => {
      await expect(() =>
        decrypt('invalid-content', bobPrivateKey, alicePublicKey)
      ).rejects.toThrow(EncryptionError);
    });

    it('should throw EncryptionError for mismatched keys', async () => {
      const encrypted = await encrypt(testMessage, alicePrivateKey, bobPublicKey);
      await expect(() =>
        decrypt(encrypted, bobPrivateKey, bobPublicKey) // wrong public key
      ).rejects.toThrow(EncryptionError);
    });
  });

  describe('createEncryptedDirectMessage', () => {
    it('should create and decrypt a direct message successfully', async () => {
      const event = await createEncryptedDirectMessage(
        testMessage,
        alicePrivateKey,
        bobPublicKey
      );

      // Extract the encrypted content from the event
      const encrypted = event.content;
      const decrypted = await decrypt(encrypted, bobPrivateKey, alicePublicKey);
      expect(decrypted).toBe(testMessage);
    });

    it('should handle empty messages', async () => {
      const event = await createEncryptedDirectMessage(
        '',
        alicePrivateKey,
        bobPublicKey
      );

      // Extract the encrypted content from the event
      const encrypted = event.content;
      const decrypted = await decrypt(encrypted, bobPrivateKey, alicePublicKey);
      expect(decrypted).toBe('');
    });

    it('should handle unicode characters', async () => {
      const unicodeMessage = '👋 Hello 世界!';
      const event = await createEncryptedDirectMessage(
        unicodeMessage,
        alicePrivateKey,
        bobPublicKey
      );

      // Extract the encrypted content from the event
      const encrypted = event.content;
      const decrypted = await decrypt(encrypted, bobPrivateKey, alicePublicKey);
      expect(decrypted).toBe(unicodeMessage);
    });
  });

  describe('Edge cases and error handling', () => {
    it('should handle long messages', async () => {
      const longMessage = 'a'.repeat(1000);
      const encrypted = await encrypt(longMessage, alicePrivateKey, bobPublicKey);
      const decrypted = await decrypt(encrypted, bobPrivateKey, alicePublicKey);
      expect(decrypted).toBe(longMessage);
    });

    it('should handle special characters', async () => {
      const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?`~';
      const encrypted = await encrypt(specialChars, alicePrivateKey, bobPublicKey);
      const decrypted = await decrypt(encrypted, bobPrivateKey, alicePublicKey);
      expect(decrypted).toBe(specialChars);
    });

    it('should throw error for null or undefined messages', async () => {
      await expect(() =>
        encrypt(null as any, alicePrivateKey, bobPublicKey)
      ).rejects.toThrow();
      
      await expect(() =>
        encrypt(undefined as any, alicePrivateKey, bobPublicKey)
      ).rejects.toThrow();
    });
  });
});