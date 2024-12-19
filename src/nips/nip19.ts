import { bech32Encode, bech32Decode, NPUB_PREFIX, NSEC_PREFIX, NOTE_PREFIX } from '../utils/encoding';

/**
 * Convert a hex public key to npub format
 */
export function hexToNpub(hex: string): string {
  return bech32Encode(NPUB_PREFIX, hex);
}

/**
 * Convert a hex private key to nsec format
 */
export function hexToNsec(hex: string): string {
  return bech32Encode(NSEC_PREFIX, hex);
}

/**
 * Convert a hex note ID to note format
 */
export function hexToNote(hex: string): string {
  return bech32Encode(NOTE_PREFIX, hex);
}

/**
 * Convert an npub to hex format
 */
export function npubToHex(npub: string): string {
  const decoded = bech32Decode(npub);
  if (decoded.type !== NPUB_PREFIX) {
    throw new Error(`Invalid npub: expected prefix ${NPUB_PREFIX}, got ${decoded.type}`);
  }
  return decoded.data;
}

/**
 * Convert an nsec to hex format
 */
export function nsecToHex(nsec: string): string {
  const decoded = bech32Decode(nsec);
  if (decoded.type !== NSEC_PREFIX) {
    throw new Error(`Invalid nsec: expected prefix ${NSEC_PREFIX}, got ${decoded.type}`);
  }
  return decoded.data;
}

/**
 * Convert a note to hex format
 */
export function noteToHex(note: string): string {
  const decoded = bech32Decode(note);
  if (decoded.type !== NOTE_PREFIX) {
    throw new Error(`Invalid note: expected prefix ${NOTE_PREFIX}, got ${decoded.type}`);
  }
  return decoded.data;
}

// Alias functions for backward compatibility
export const npubEncode = hexToNpub;
export const nsecEncode = hexToNsec;
export const noteEncode = hexToNote;
export const npubDecode = npubToHex;
export const nsecDecode = nsecToHex;
export const noteDecode = noteToHex;

/**
 * Decodes a bech32-encoded Nostr identifier
 * @param {string} nip19 - The bech32-encoded string to decode
 * @returns {Object} An object containing the type and decoded data
 * @example
 * const decoded = decode("npub1...");
 * console.log(decoded.type);  // "npub"
 * console.log(decoded.data);  // hex-encoded public key
 */
export function decodeNip19(nip19: string): { type: string; data: string } {
  const decoded = bech32Decode(nip19);
  return {
    type: decoded.type,
    data: decoded.data
  };
}
