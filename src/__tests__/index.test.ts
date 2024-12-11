import { describe, it, expect, beforeAll, vi } from 'vitest';
import {
  generateKeyPairWithSeed,
  seedPhraseToKeyPair,
  validateSeedPhrase,
  nsecToHex,
  npubToHex,
  hexToNsec,
  hexToNpub,
  signMessage,
  verifySignature,
  createEvent,
  verifyEvent,
  configureHMAC,
  fromHex
} from '../index';

vi.mock('@noble/secp256k1', async () => {
  const utils = {
    hmacSha256: (_key: Uint8Array, ..._messages: Uint8Array[]): Uint8Array => {
      const result = new Uint8Array(32);
      result.fill(1);
      return result;
    },
    hmacSha256Sync: (_key: Uint8Array, ..._messages: Uint8Array[]): Uint8Array => {
      const result = new Uint8Array(32);
      result.fill(1);
      return result;
    }
  };

  return {
    utils,
    sign: async (message: Uint8Array) => ({
      toCompactRawBytes: () => message // Return the message as the signature for testing
    }),
    verify: async (signature: Uint8Array, message: Uint8Array) => {
      // Compare the signature with the message for testing
      // In our mock, signature should match message for valid verification
      if (signature.length !== message.length) return false;
      return signature.every((byte, i) => byte === message[i]);
    }
  };
});

describe('nostr-nsec-seedphrase', () => {
  beforeAll(() => {
    // Configure HMAC before running tests
    configureHMAC();
  });

  describe('Key Generation', () => {
    it('should generate a valid key pair with seed phrase', () => {
      const keyPair = generateKeyPairWithSeed();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.nsec).toMatch(/^nsec1/);
      expect(keyPair.npub).toMatch(/^npub1/);
      expect(keyPair.seedPhrase.split(' ')).toHaveLength(12);
    });

    it('should convert seed phrase to key pair', () => {
      const keyPair = generateKeyPairWithSeed();
      const recoveredKeyPair = seedPhraseToKeyPair(keyPair.seedPhrase);
      expect(recoveredKeyPair.privateKey).toBe(keyPair.privateKey);
      expect(recoveredKeyPair.publicKey).toBe(keyPair.publicKey);
      expect(recoveredKeyPair.nsec).toBe(keyPair.nsec);
      expect(recoveredKeyPair.npub).toBe(keyPair.npub);
    });

    it('should validate seed phrases', () => {
      const keyPair = generateKeyPairWithSeed();
      expect(validateSeedPhrase(keyPair.seedPhrase)).toBe(true);
      expect(validateSeedPhrase('invalid seed phrase')).toBe(false);
    });
  });

  describe('Format Conversions', () => {
    it('should convert between hex and nsec/npub formats', () => {
      const keyPair = generateKeyPairWithSeed();
      
      // Test hex to nsec/npub
      const nsec = hexToNsec(keyPair.privateKey);
      const npub = hexToNpub(keyPair.publicKey);
      expect(nsec).toBe(keyPair.nsec);
      expect(npub).toBe(keyPair.npub);

      // Test nsec/npub to hex
      const privateKeyHex = nsecToHex(keyPair.nsec);
      const publicKeyHex = npubToHex(keyPair.npub);
      expect(privateKeyHex).toBe(keyPair.privateKey);
      expect(publicKeyHex).toBe(keyPair.publicKey);
    });

    it('should create key pair from hex', () => {
      const originalKeyPair = generateKeyPairWithSeed();
      const keyPair = fromHex(originalKeyPair.privateKey);
      expect(keyPair.privateKey).toBe(originalKeyPair.privateKey);
      expect(keyPair.publicKey).toBe(originalKeyPair.publicKey);
      expect(keyPair.nsec).toBe(originalKeyPair.nsec);
      expect(keyPair.npub).toBe(originalKeyPair.npub);
    });
  });

  describe('Message Signing', () => {
    it('should sign and verify messages', async () => {
      const keyPair = generateKeyPairWithSeed();
      const message = 'Hello, Nostr!';
      
      const signature = await signMessage(message, keyPair.privateKey);
      expect(signature).toBeDefined();
      
      const isValid = await verifySignature(message, signature, keyPair.publicKey);
      expect(isValid).toBe(true);
    });

    it('should fail verification for invalid signatures', async () => {
      const keyPair = generateKeyPairWithSeed();
      const message = 'Hello, Nostr!';
      const wrongMessage = 'Wrong message';
      
      const signature = await signMessage(message, keyPair.privateKey);
      const isValid = await verifySignature(wrongMessage, signature, keyPair.publicKey);
      expect(isValid).toBe(false);
    });
  });

  describe('Event Handling', () => {
    it('should create and verify events', async () => {
      const keyPair = generateKeyPairWithSeed();
      const event = await createEvent(
        'Hello, Nostr!',
        1,
        keyPair.privateKey,
        [['t', 'test']]
      );

      expect(event.pubkey).toBe(keyPair.publicKey);
      expect(event.kind).toBe(1);
      expect(event.content).toBe('Hello, Nostr!');
      expect(event.tags).toEqual([['t', 'test']]);
      expect(event.id).toBeDefined();
      expect(event.sig).toBeDefined();

      const isValid = await verifyEvent(event);
      expect(isValid).toBe(true);
    });

    it('should detect tampered events', async () => {
      const keyPair = generateKeyPairWithSeed();
      const event = await createEvent(
        'Hello, Nostr!',
        1,
        keyPair.privateKey
      );

      // Tamper with the content
      event.content = 'Tampered content';

      const isValid = await verifyEvent(event);
      expect(isValid).toBe(false);
    });
  });

  describe('HMAC Configuration', () => {
    it('should configure HMAC without errors', () => {
      expect(() => configureHMAC()).not.toThrow();
    });
  });
});
