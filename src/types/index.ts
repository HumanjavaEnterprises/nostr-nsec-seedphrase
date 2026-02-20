/**
 * @module types
 * @description Type definitions for the nostr-nsec-seedphrase library
 */

// Export events types
export type { NostrEvent, ValidationResult } from "./events.js";

// Export key types
export type { KeyPair, PublicKeyDetails } from "./keys.js";

// NIP-19 data type
export type Nip19DataType =
  | "npub"
  | "nsec"
  | "note"
  | "nprofile"
  | "nevent"
  | "naddr"
  | "nrelay";
