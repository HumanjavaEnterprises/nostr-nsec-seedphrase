import { describe, it, expect } from 'vitest';
import { NostrProviderImpl } from '../../nips/nip07';
import { generatePrivateKey } from '../../crypto/keys';
import { TEST_CONSTANTS } from '../test-utils';

describe('NIP-07: Web Browser Key Management', () => {
  let provider: NostrProviderImpl;
  const testPrivateKey = generatePrivateKey();

  beforeEach(() => {
    provider = new NostrProviderImpl(testPrivateKey);
  });

  describe('getPublicKey', () => {
    it('should return a valid public key', async () => {
      const publicKey = await provider.getPublicKey();
      expect(publicKey).toBeDefined();
      expect(typeof publicKey).toBe('string');
      expect(publicKey.length).toBe(64);
    });
  });

  describe('signEvent', () => {
    it('should sign events correctly', async () => {
      const event = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: 'Hello, Nostr!',
        pubkey: '',
        id: '',
        sig: ''
      };

      const signedEvent = await provider.signEvent(event);
      expect(signedEvent.sig).toBeDefined();
      expect(signedEvent.id).toBeDefined();
      expect(signedEvent.pubkey).toBeDefined();
      expect(typeof signedEvent.sig).toBe('string');
      expect(signedEvent.sig.length).toBe(128);
    });

    it('should reject invalid events', async () => {
      const invalidEvent = {
        kind: 1,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: '',
        pubkey: TEST_CONSTANTS.PUBLIC_KEY,
        id: 'invalid',
        sig: 'invalid'
      };

      await expect(provider.signEvent(invalidEvent)).rejects.toThrow();
    });
  });

  describe('getRelays', () => {
    it('should return relay information', async () => {
      const relays = await provider.getRelays();
      expect(relays).toBeDefined();
      expect(typeof relays).toBe('object');
    });
  });

  describe('nip04', () => {
    it('should encrypt and decrypt messages', async () => {
      const recipientPubkey = TEST_CONSTANTS.PUBLIC_KEY;
      const message = 'Hello, Nostr!';

      const encrypted = await provider.nip04.encrypt(recipientPubkey, message);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');

      const decrypted = await provider.nip04.decrypt(recipientPubkey, encrypted);
      expect(decrypted).toBe(message);
    });
  });
});
