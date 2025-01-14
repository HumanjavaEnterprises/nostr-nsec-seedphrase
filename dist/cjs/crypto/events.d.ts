/**
 * @module crypto/events
 * @description Event signing and verification functions for Nostr
 */
import type { NostrEvent, UnsignedEvent } from '../types/events.js';
import { ValidationResult } from '../types/keys.js';
/**
 * Calculates the event hash/ID according to the Nostr protocol
 * @param event - The event to hash
 * @returns The hex-encoded event hash
 */
export declare function getEventHash(event: UnsignedEvent): string;
/**
 * Creates an unsigned event
 * @param pubkey - The public key of the event creator
 * @param content - The event content
 * @param kind - The event kind (defaults to TEXT_NOTE)
 * @param tags - The event tags (defaults to empty array)
 * @returns An unsigned event
 */
export declare function createUnsignedEvent(pubkey: string, content: string, kind?: number, tags?: string[][]): UnsignedEvent;
/**
 * Signs a Nostr event using Schnorr signatures
 * @param event - The event to sign
 * @param privateKey - The hex-encoded private key to sign with
 * @returns The signed event
 * @throws {Error} If signing fails
 */
export declare function signEvent(event: UnsignedEvent, privateKey: string): Promise<NostrEvent>;
/**
 * Verifies a Nostr event signature
 * @param event - The event to verify
 * @returns Validation result
 */
export declare function verifyEvent(event: NostrEvent): Promise<ValidationResult>;
/**
 * Signs a message with a private key using Schnorr signatures
 * @param message - The message to sign
 * @param privateKey - The hex-encoded private key to sign with
 * @returns The hex-encoded signature
 * @throws {Error} If signing fails
 */
export declare function signMessage(message: string, privateKey: string): Promise<string>;
/**
 * Verifies a message signature using Schnorr verification
 * @param message - The original message
 * @param signature - The hex-encoded signature to verify
 * @param publicKey - The hex-encoded public key to verify against
 * @returns Validation result
 */
export declare function verifySignature(message: string, signature: string, publicKey: string): Promise<ValidationResult>;
