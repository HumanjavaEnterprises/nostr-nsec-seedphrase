/**
 * @module types/keys
 * @description Key-related type definitions
 */

/**
 * Public key can be either a hex string or a detailed object
 */
export type PublicKey = string | PublicKeyDetails;

/**
 * Public key in hex format
 */
export type PublicKeyHex = string;

/**
 * Detailed public key information
 */
export interface PublicKeyDetails {
  /** Hex-encoded public key */
  hex: string;
  /** Compressed public key (33 bytes with prefix) */
  compressed: Uint8Array;
  /** Schnorr public key (32 bytes x-coordinate) as per BIP340 */
  schnorr: Uint8Array;
  /** Bech32-encoded npub format */
  npub: string;
}

/**
 * Key pair used for signing and encryption
 * @see https://github.com/nostr-protocol/nips/blob/master/01.md
 */
export interface KeyPair {
  /** Private key in hex format */
  privateKey: string;
  /** Public key details */
  publicKey: PublicKeyDetails;
  /** Private key in bech32 nsec format */
  nsec: string;
  /** BIP39 seed phrase used to generate this key pair (if available) */
  seedPhrase?: string;
}

/**
 * Result of decoding a bech32 string
 */
export interface Bech32Result {
  /** Type of the decoded data (e.g., 'npub', 'nsec', 'note') */
  type: string;
  /** The decoded data */
  data: Uint8Array;
}

/**
 * Result of key pair validation
 */
export interface ValidationResult {
  /** Whether the validation passed */
  isValid: boolean;
  /** Error message if validation failed */
  error?: string;
}
