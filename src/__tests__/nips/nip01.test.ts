import { describe, test, expect } from 'vitest';
import {
  createUnsignedEvent,
  createNip01SignedEvent,
  signEvent,
  verifyEventSignature,
  getEventHash
} from '../../nips/nip01';
import { UnsignedEvent, NostrEvent } from '../../types/events';
import { getPublicKey } from '../../crypto/keys';

describe('NIP-01: Basic Protocol Flow', () => {
  const testPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const testPublicKey = getPublicKey(testPrivateKey);

  test('createUnsignedEvent creates valid event', () => {
    const event = createUnsignedEvent(
      testPublicKey,
      1,
      'Hello, Nostr!',
      [['p', testPublicKey]]
    );

    expect(event.pubkey).toBe(testPublicKey);
    expect(event.kind).toBe(1);
    expect(event.content).toBe('Hello, Nostr!');
    expect(event.tags).toEqual([['p', testPublicKey]]);
    expect(event.created_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
  });

  test('signEvent signs event correctly', async () => {
    const unsignedEvent = createUnsignedEvent(
      testPublicKey,
      1,
      'Hello, Nostr!'
    );

    const signedEvent = await signEvent(unsignedEvent, testPrivateKey);
    expect(signedEvent.id).toBeDefined();
    expect(signedEvent.sig).toBeDefined();
    expect(signedEvent.sig).toHaveLength(128);
    expect(signedEvent.sig).toMatch(/^[0-9a-f]{128}$/);
  });

  test('createNip01SignedEvent creates valid signed event', async () => {
    const event = await createNip01SignedEvent(
      testPublicKey,
      1,
      'Hello, Nostr!',
      testPrivateKey
    );

    expect(event.pubkey).toBe(testPublicKey);
    expect(event.kind).toBe(1);
    expect(event.content).toBe('Hello, Nostr!');
    expect(event.id).toBeDefined();
    expect(event.sig).toBeDefined();
    expect(event.sig).toHaveLength(128);
  });

  test('verifyEventSignature verifies valid signature', async () => {
    const event = await createNip01SignedEvent(
      testPublicKey,
      1,
      'Hello, Nostr!',
      testPrivateKey
    );

    const isValid = await verifyEventSignature(event);
    expect(isValid).toBe(true);
  });

  test('verifyEventSignature rejects invalid signature', async () => {
    const event = await createNip01SignedEvent(
      testPublicKey,
      1,
      'Hello, Nostr!',
      testPrivateKey
    );

    const tamperedEvent = {
      ...event,
      content: 'Tampered content'
    };

    const isValid = await verifyEventSignature(tamperedEvent);
    expect(isValid).toBe(false);
  });

  test('getEventHash generates consistent hash', () => {
    const event = createUnsignedEvent(
      testPublicKey,
      1,
      'Hello, Nostr!'
    );

    const hash1 = getEventHash(event);
    const hash2 = getEventHash(event);
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
  });
});
