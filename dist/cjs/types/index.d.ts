/**
 * @module types
 * @description Type definitions for the nostr-nsec-seedphrase library
 */
export type { NostrEvent, ValidationResult } from './events.js';
export type { KeyPair, PublicKeyDetails } from './keys.js';
export type Nip19DataType = 'npub' | 'nsec' | 'note' | 'nprofile' | 'nevent' | 'naddr' | 'nrelay';
