/**
 * @module types
 * @description Type definitions for the nostr-nsec-seedphrase library
 */

// Export events types
export type { 
  NostrEvent,
  ValidationResult 
} from './events.js';

// Export key types
export type {
  KeyPair,
  PublicKeyDetails
} from './keys.js';

// Import and re-export Nip19Data type from nostr-crypto-utils
export type { Nip19Data } from 'nostr-crypto-utils';
