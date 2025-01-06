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

// Import and re-export NIP-19 type from nostr-crypto-utils
export type { Nip19DataType } from 'nostr-crypto-utils';
