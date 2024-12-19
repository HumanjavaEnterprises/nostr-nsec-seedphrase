import {
  NostrProvider,
  initializeProvider,
  getNostrProvider,
  getPublicKeyFromProvider
} from '../../nips/nip07';
import { UnsignedEvent } from '../../types/events';
import { createEncryptedDirectMessage, decrypt } from '../../nips/nip04';

describe('NIP-07: window.nostr capability', () => {
  const testPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  let provider: NostrProvider;

  beforeEach(() => {
    initializeProvider(testPrivateKey);
    const nostrProvider = getNostrProvider();
    if (!nostrProvider) {
      throw new Error('Provider not initialized');
    }
    provider = nostrProvider;
  });

  test('getPublicKey returns valid public key', async () => {
    const pubkey = await provider.getPublicKey();
    expect(pubkey).toBeDefined();
    expect(pubkey).toHaveLength(64);
    expect(pubkey).toMatch(/^[0-9a-f]{64}$/);
  });

  test('signEvent signs event correctly', async () => {
    const unsignedEvent: UnsignedEvent = {
      pubkey: await provider.getPublicKey(),
      created_at: Math.floor(Date.now() / 1000),
      kind: 1,
      tags: [],
      content: 'Hello, Nostr!'
    };

    const signedEvent = await provider.signEvent(unsignedEvent);
    expect(signedEvent.id).toBeDefined();
    expect(signedEvent.sig).toBeDefined();
    expect(signedEvent.sig).toHaveLength(128);
    expect(signedEvent.sig).toMatch(/^[0-9a-f]{128}$/);
  });

  test('encrypt/decrypt works correctly', async () => {
    const pubkey = await provider.getPublicKey();
    const plaintext = 'Hello, Nostr!';
    
    const encrypted = await provider.encrypt(pubkey, plaintext);
    expect(encrypted).toBeDefined();
    
    const decrypted = await provider.decrypt(pubkey, encrypted);
    expect(decrypted).toBe(plaintext);
  });

  test('signSchnorr/verifySchnorr works correctly', async () => {
    const pubkey = await provider.getPublicKey();
    const message = 'Hello, Nostr!';
    
    const signature = await provider.signSchnorr(message);
    expect(signature).toBeDefined();
    expect(signature).toHaveLength(128);
    
    const isValid = await provider.verifySchnorr(signature, message, pubkey);
    expect(isValid).toBe(true);
  });

  test('getRelays returns valid relay list', async () => {
    const relays = await provider.getRelays();
    expect(relays).toBeDefined();
    expect(Object.keys(relays).length).toBeGreaterThan(0);
    
    for (const [url, policy] of Object.entries(relays)) {
      expect(url).toMatch(/^wss:\/\//);
      expect(policy.read).toBeDefined();
      expect(policy.write).toBeDefined();
    }
  });
});
