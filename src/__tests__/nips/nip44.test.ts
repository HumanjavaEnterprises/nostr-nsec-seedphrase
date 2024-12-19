import { describe, it, expect, beforeEach } from 'vitest';
import { generatePrivateKey, getPublicKey } from '../../crypto/keys';
import {
  encrypt,
  decrypt,
  encryptWithPassword,
  decryptWithPassword,
  deriveKey
} from '../../nips/nip44';

describe('NIP-44: Encrypted Direct Messages v2', () => {
  let senderPrivateKey: string;
  let senderPublicKey: string;
  let recipientPrivateKey: string;
  let recipientPublicKey: string;

  beforeEach(() => {
    senderPrivateKey = generatePrivateKey();
    senderPublicKey = getPublicKey(senderPrivateKey);
    recipientPrivateKey = generatePrivateKey();
    recipientPublicKey = getPublicKey(recipientPrivateKey);
  });

  describe('Message Encryption/Decryption', () => {
    it('should encrypt and decrypt a message successfully', async () => {
      const message = 'Hello, this is a secret message!';
      
      const encrypted = await encrypt(message, senderPrivateKey, recipientPublicKey);
      expect(encrypted).toBeTruthy();
      
      const decrypted = await decrypt(encrypted, recipientPrivateKey, senderPublicKey);
      expect(decrypted).toBe(message);
    });

    it('should produce different ciphertexts for the same message', async () => {
      const message = 'Hello, this is a secret message!';
      
      const encrypted1 = await encrypt(message, senderPrivateKey, recipientPublicKey);
      const encrypted2 = await encrypt(message, senderPrivateKey, recipientPublicKey);
      
      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should throw error for invalid keys', async () => {
      const message = 'Hello, this is a secret message!';
      
      expect(async () => {
        await encrypt(message, 'invalid-key', recipientPublicKey)
      }).rejects.toThrow();
      expect(async () => {
        await encrypt(message, senderPrivateKey, 'invalid-key')
      }).rejects.toThrow();
    });
  });

  describe('Password-based Encryption/Decryption', () => {
    it('should encrypt and decrypt with password successfully', async () => {
      const message = 'Hello, this is a secret message!';
      const password = 'test-password-123';
      
      const encrypted = await encryptWithPassword(message, password);
      expect(encrypted).toBeTruthy();
      
      const decrypted = await decryptWithPassword(encrypted, password);
      expect(decrypted).toBe(message);
    });

    it('should produce different ciphertexts for the same message and password', async () => {
      const message = 'Hello, this is a secret message!';
      const password = 'test-password-123';
      
      const encrypted1 = await encryptWithPassword(message, password);
      const encrypted2 = await encryptWithPassword(message, password);
      
      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should throw error for wrong password', async () => {
      const message = 'Hello, this is a secret message!';
      const password = 'test-password-123';
      const wrongPassword = 'wrong-password-456';
      
      const encrypted = await encryptWithPassword(message, password);
      expect(async () => {
        await decryptWithPassword(encrypted, wrongPassword)
      }).rejects.toThrow();
    });
  });

  describe('Key Derivation', () => {
    it('should derive consistent keys from the same password and salt', async () => {
      const password = 'test-password-123';
      
      const { key: key1, salt } = await deriveKey(password);
      const { key: key2 } = await deriveKey(password, salt);
      
      expect(key1).toEqual(key2);
    });

    it('should derive different keys from different passwords with same salt', async () => {
      const password1 = 'test-password-123';
      const password2 = 'different-password-456';
      const { salt } = await deriveKey(password1);
      
      const { key: key1 } = await deriveKey(password1, salt);
      const { key: key2 } = await deriveKey(password2, salt);
      
      expect(key1).not.toEqual(key2);
    });

    it('should derive different keys with different salts', async () => {
      const password = 'test-password-123';
      
      const { key: key1 } = await deriveKey(password);
      const { key: key2 } = await deriveKey(password);
      
      expect(key1).not.toEqual(key2);
    });
  });
});
