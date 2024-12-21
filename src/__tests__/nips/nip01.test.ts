import { describe, it, expect, beforeAll } from 'vitest';
import { TEST_CONSTANTS, mockSecp256k1, setupHMAC } from '../test-utils';
import { 
  createUnsignedEvent,
  signEvent,
  createNip01SignedEvent,
  verifyEventSignature,
  getEventHash
} from '../../nips/nip01';

describe('NIP-01: Basic Protocol Flow', () => {
  beforeAll(() => {
    setupHMAC();
  });

  it('createUnsignedEvent creates valid event', () => {
    const event = createUnsignedEvent(
      TEST_CONSTANTS.PUBLIC_KEY,
      1,
      'Hello, Nostr!',
      []
    );

    expect(event).toBeDefined();
    expect(event.pubkey).toBe(TEST_CONSTANTS.PUBLIC_KEY);
    expect(event.kind).toBe(1);
    expect(event.content).toBe('Hello, Nostr!');
    expect(Array.isArray(event.tags)).toBe(true);
    expect(typeof event.created_at).toBe('number');
  });

  it('signEvent signs event correctly', async () => {
    const unsignedEvent = createUnsignedEvent(
      TEST_CONSTANTS.PUBLIC_KEY,
      1,
      'Hello, Nostr!',
      []
    );

    const signedEvent = await signEvent(unsignedEvent, TEST_CONSTANTS.PRIVATE_KEY);
    expect(signedEvent.sig).toBeDefined();
    expect(typeof signedEvent.sig).toBe('string');
    expect(signedEvent.sig.length).toBe(128);
  });

  it('createNip01SignedEvent creates valid signed event', async () => {
    const event = await createNip01SignedEvent(
      TEST_CONSTANTS.PUBLIC_KEY,
      1,
      'Hello, Nostr!',
      TEST_CONSTANTS.PRIVATE_KEY,
      []
    );

    expect(event).toBeDefined();
    expect(event.pubkey).toBe(TEST_CONSTANTS.PUBLIC_KEY);
    expect(event.kind).toBe(1);
    expect(event.content).toBe('Hello, Nostr!');
    expect(Array.isArray(event.tags)).toBe(true);
    expect(typeof event.created_at).toBe('number');
    expect(event.sig).toBeDefined();
    expect(typeof event.sig).toBe('string');
    expect(event.sig.length).toBe(128);
  });

  it('verifyEventSignature verifies valid signature', async () => {
    const event = await createNip01SignedEvent(
      TEST_CONSTANTS.PUBLIC_KEY,
      1,
      'Hello, Nostr!',
      TEST_CONSTANTS.PRIVATE_KEY,
      []
    );

    const isValid = await verifyEventSignature(event);
    expect(isValid).toBe(true);
  });

  it('verifyEventSignature rejects invalid signature', async () => {
    const event = await createNip01SignedEvent(
      TEST_CONSTANTS.PUBLIC_KEY,
      1,
      'Hello, Nostr!',
      TEST_CONSTANTS.PRIVATE_KEY,
      []
    );

    // Tamper with the signature
    event.sig = event.sig.replace('0', '1');

    const isValid = await verifyEventSignature(event);
    expect(isValid).toBe(false);
  });

  it('getEventHash generates consistent hash', () => {
    const event = createUnsignedEvent(
      TEST_CONSTANTS.PUBLIC_KEY,
      1,
      'Hello, Nostr!',
      []
    );

    const hash1 = getEventHash(event);
    const hash2 = getEventHash(event);
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64);
  });
});
