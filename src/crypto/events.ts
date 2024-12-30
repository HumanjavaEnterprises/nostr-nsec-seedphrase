/**
 * @module crypto/events
 * @description Event signing and verification functions for Nostr
 */

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { logger } from '../utils/logger.js';
import type { NostrEvent, UnsignedEvent } from '../types/events.js';
import { ValidationResult } from '../types/keys.js';
import { Defaults } from '../constants.js';

/**
 * Calculates the event hash/ID according to the Nostr protocol
 * @param event - The event to hash
 * @returns The hex-encoded event hash
 */
export function getEventHash(event: UnsignedEvent): string {
  try {
    const serialized = JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content,
    ]);
    return bytesToHex(sha256(new TextEncoder().encode(serialized)));
  } catch (error) {
    logger.error('Failed to calculate event hash:', error);
    throw error;
  }
}

/**
 * Creates an unsigned event
 * @param pubkey - The public key of the event creator
 * @param content - The event content
 * @param kind - The event kind (defaults to TEXT_NOTE)
 * @param tags - The event tags (defaults to empty array)
 * @returns An unsigned event
 */
export function createUnsignedEvent(
  pubkey: string,
  content: string,
  kind: number = Defaults.KIND,
  tags: string[][] = Defaults.TAGS,
): UnsignedEvent {
  return {
    pubkey,
    created_at: Defaults.CREATED_AT(),
    kind,
    tags,
    content,
  };
}

/**
 * Signs a Nostr event using Schnorr signatures
 * @param event - The event to sign
 * @param privateKey - The hex-encoded private key to sign with
 * @returns The signed event
 * @throws {Error} If signing fails
 */
export async function signEvent(
  event: UnsignedEvent,
  privateKey: string,
): Promise<NostrEvent> {
  try {
    const id = getEventHash(event);
    const sig = bytesToHex(
      await schnorr.sign(
        hexToBytes(id),
        hexToBytes(privateKey)
      )
    );

    logger.log('Event signed successfully');
    return {
      ...event,
      id,
      sig,
    };
  } catch (error) {
    logger.error('Failed to sign event:', error);
    throw error;
  }
}

/**
 * Verifies a Nostr event signature
 * @param event - The event to verify
 * @returns Validation result
 */
export async function verifyEvent(event: NostrEvent): Promise<ValidationResult> {
  try {
    if (!event.id || !event.pubkey || !event.sig) {
      return {
        isValid: false,
        error: 'Missing required fields',
      };
    }

    const hash = getEventHash(event);
    if (hash !== event.id) {
      return {
        isValid: false,
        error: 'Event hash mismatch',
      };
    }

    logger.log('Verifying event signature');
    const isValid = await schnorr.verify(
      hexToBytes(event.sig),
      hexToBytes(hash),
      hexToBytes(event.pubkey)
    );

    return {
      isValid,
      error: isValid ? undefined : 'Invalid signature',
    };
  } catch (error) {
    logger.error('Failed to verify event:', error);
    return {
      isValid: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Signs a message with a private key using Schnorr signatures
 * @param message - The message to sign
 * @param privateKey - The hex-encoded private key to sign with
 * @returns The hex-encoded signature
 * @throws {Error} If signing fails
 */
export async function signMessage(
  message: string,
  privateKey: string,
): Promise<string> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    const signature = await schnorr.sign(
      messageHash,
      hexToBytes(privateKey)
    );
    logger.log('Message signed successfully');
    return bytesToHex(signature);
  } catch (error) {
    logger.error('Failed to sign message:', error);
    throw error;
  }
}

/**
 * Verifies a message signature using Schnorr verification
 * @param message - The original message
 * @param signature - The hex-encoded signature to verify
 * @param publicKey - The hex-encoded public key to verify against
 * @returns Validation result
 */
export async function verifySignature(
  message: string,
  signature: string,
  publicKey: string,
): Promise<ValidationResult> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    logger.log('Verifying message signature');
    const isValid = await schnorr.verify(
      hexToBytes(signature),
      messageHash,
      hexToBytes(publicKey)
    );

    return {
      isValid,
      error: isValid ? undefined : 'Invalid signature',
    };
  } catch (error) {
    logger.error('Failed to verify signature:', error);
    return {
      isValid: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
