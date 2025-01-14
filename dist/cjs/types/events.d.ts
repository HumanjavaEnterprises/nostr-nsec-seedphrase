/**
 * Represents a signed Nostr event
 * @interface
 * @see https://github.com/nostr-protocol/nips/blob/master/01.md
 */
export interface NostrEvent {
    /** Event ID (32-bytes lowercase hex of the sha256 of the serialized event data) */
    id: string;
    /** Event creator's public key (32-bytes lowercase hex) */
    pubkey: string;
    /** Unix timestamp in seconds */
    created_at: number;
    /** Event kind (integer) */
    kind: number;
    /** Array of arrays of strings (event tags) */
    tags: string[][];
    /** Event content (arbitrary string) */
    content: string;
    /** Schnorr signature of the event ID (64-bytes hex) */
    sig: string;
}
/**
 * Represents an unsigned Nostr event before signing
 * @interface
 */
export interface UnsignedEvent {
    /** Event creator's public key (32-bytes lowercase hex) */
    pubkey: string;
    /** Unix timestamp in seconds */
    created_at: number;
    /** Event kind (integer) */
    kind: number;
    /** Array of arrays of strings (event tags) */
    tags: string[][];
    /** Event content (arbitrary string) */
    content: string;
}
/**
 * @module types/events
 * @description Event-related type definitions
 */
/**
 * Result of event validation
 */
export interface ValidationResult {
    /** Whether the validation passed */
    isValid: boolean;
    /** Error message if validation failed */
    error?: string;
}
/**
 * Tag type for Nostr events
 */
export type Tag = string[];
/**
 * Unsigned Nostr event
 */
export interface UnsignedEvent {
    /** Public key of the event creator */
    pubkey: string;
    /** Unix timestamp in seconds */
    created_at: number;
    /** Event kind (1 for text note, etc.) */
    kind: number;
    /** Array of tags */
    tags: Tag[];
    /** Content of the event */
    content: string;
}
/**
 * Complete Nostr event with signature
 */
export interface NostrEvent extends UnsignedEvent {
    /** Event ID (32-byte SHA256 hash of the serialized event data) */
    id: string;
    /** Schnorr signature of the event ID */
    sig: string;
}
