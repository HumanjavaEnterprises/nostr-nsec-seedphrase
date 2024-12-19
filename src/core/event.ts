import { NostrEvent, UnsignedEvent, EventKind } from "../types/events";
import { getPublicKey } from "../crypto/keys";
import { createEventSignature } from "../crypto/signing";
import { validateUnsignedEvent } from "./validation";
import { sha256 } from "@noble/hashes/sha256";
import { utf8Encoder, toHex } from "../utils/encoding";
import { bytesToHex, hexToBytes } from "../utils/encoding";
import * as secp256k1 from "@noble/secp256k1";

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

  const validation = validateUnsignedEvent(event);
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
    const hash = hexToBytes(event.id);
    const signature = hexToBytes(event.sig);
    const publicKey = hexToBytes(event.pubkey);
    
    return await secp256k1.verify(signature, hash, publicKey);
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to verify signature: ${error.message}`);
    }
    throw new Error('Failed to verify signature: Unknown error');
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