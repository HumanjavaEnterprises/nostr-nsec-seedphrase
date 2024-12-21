import { NostrEvent, UnsignedEvent, EventKind, EventValidationResult } from "../types/events";
import { getPublicKey } from "../crypto/keys";
import { createEventSignature } from "../crypto/signing";
import { validateUnsignedEvent as validateUnsignedEventFromValidation } from "./validation";
import { sha256 } from "@noble/hashes/sha256";
import { utf8Encoder, toHex } from "../utils/encoding";
import { bytesToHex, hexToBytes } from "../utils/encoding";
import * as secp256k1 from "@noble/secp256k1";
import { hmac } from '@noble/hashes/hmac';

export class EventCreationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EventCreationError';
  }
}

export function createUnsignedEvent(
  content: string,
  kind: EventKind,
  privateKey: string,
  tags: string[][] = []
): UnsignedEvent {
  const pubkey = getPublicKey(privateKey);
  
  const event: UnsignedEvent = {
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind,
    tags,
    content,
  };

  const validation = validateUnsignedEventFromValidation(event);
  if (!validation.isValid) {
    throw new EventCreationError(
      `Invalid event structure: ${validation.errors.join(', ')}`
    );
  }

  return event;
}

export async function createSignedEvent(
  content: string,
  kind: EventKind,
  privateKey: string,
  tags: string[][] = []
): Promise<NostrEvent> {
  try {
    const unsignedEvent = createUnsignedEvent(content, kind, privateKey, tags);
    const signedEvent = await signEvent(unsignedEvent, privateKey);
    return signedEvent;
  } catch (error) {
    throw new EventCreationError(
      `Failed to create signed event: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
}

/**
 * Get the event hash ID
 */
export function getEventHash(event: UnsignedEvent): string {
  try {
    const serializedEvent = JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content
    ]);
    
    const hash = sha256(Buffer.from(serializedEvent));
    return bytesToHex(hash);
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to get event hash: ${error.message}`);
    }
    throw new Error('Failed to get event hash: Unknown error');
  }
}

/**
 * Sign an event with a private key
 */
export async function signEvent(event: UnsignedEvent, privateKey: string): Promise<NostrEvent> {
  try {
    const eventHash = getEventHash(event);
    const signature = await secp256k1.sign(hexToBytes(eventHash), privateKey);
    const signatureBytes = signature.toCompactRawBytes();
    
    return {
      ...event,
      id: eventHash,
      sig: bytesToHex(signatureBytes)
    };
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to sign event: ${error.message}`);
    }
    throw new Error('Failed to sign event: Unknown error');
  }
}

/**
 * Verify an event signature
 */
export async function verifyEventSignature(event: NostrEvent): Promise<boolean> {
  try {
    // Compute the event hash from the event data
    const computedHash = sha256(Buffer.from(JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content
    ])));

    // Verify that the computed hash matches the event ID
    if (bytesToHex(computedHash) !== event.id) {
      return false;
    }

    const signature = hexToBytes(event.sig);
    const publicKey = hexToBytes(event.pubkey);
    
    return await secp256k1.verify(signature, computedHash, publicKey);
  } catch (error) {
    console.error('Failed to verify signature:', error);
    return false;
  }
}

/**
 * Create an unsigned event
 */
export function createUnsignedEventFromPubkey(
  pubkey: string,
  kind: number,
  content: string,
  tags: string[][] = []
): UnsignedEvent {
  return {
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind,
    tags,
    content,
  };
}

/**
 * Validate an unsigned event according to Nostr protocol
 */
import { validateUnsignedEvent } from "./validation";

/**
 * Validate a signed event according to Nostr protocol
 */
export async function validateSignedEvent(event: NostrEvent): Promise<EventValidationResult> {
  const errors: string[] = [];

  // First validate as unsigned event
  const unsignedValidation = validateUnsignedEventFromValidation(event);
  errors.push(...unsignedValidation.errors);

  // Check signature-specific fields
  if (!event.id) errors.push('Missing id');
  if (!event.sig) errors.push('Missing signature');

  // Verify event hash
  const calculatedId = getEventHash(event);
  if (event.id !== calculatedId) {
    errors.push('Invalid event hash');
  }

  // Verify signature
  if (event.sig) {
    try {
      const isValid = await verifyEventSignature(event);
      if (!isValid) {
        errors.push('Invalid signature');
      }
    } catch (error) {
      errors.push(`Signature verification failed: ${error instanceof Error ? error.message : 'unknown error'}`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Validate any event (signed or unsigned)
 */
export function validateEvent(event: UnsignedEvent | NostrEvent): Promise<EventValidationResult> {
  if ('sig' in event) {
    return validateSignedEvent(event);
  }
  return Promise.resolve(validateUnsignedEventFromValidation(event));
}