/**
 * NIP-19: bech32-encoded entities
 * @module nip19
 * @description Implements NIP-19 specification for bech32-encoded entities in Nostr.
 * Provides encoding and decoding functions for npub (public keys), nsec (private keys),
 * and note (event IDs) formats.
 * @see https://github.com/nostr-protocol/nips/blob/master/19.md
 */

import { logger } from "../utils/logger.js";
import { nip19 } from "nostr-crypto-utils";

const { npubEncode, nsecEncode, noteEncode, decode: nip19Decode } = nip19;
type Nip19DataType =
  | "npub"
  | "nsec"
  | "note"
  | "nprofile"
  | "nevent"
  | "naddr"
  | "nrelay";

/**
 * Encodes a public key into npub format
 * @param {string} hex - The hex-encoded public key
 * @returns {string} The bech32-encoded npub string
 * @throws {Error} If encoding fails
 * @example
 * const npub = hexToNpub('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
 * returns 'npub1...'
 */
export function hexToNpub(hex: string): string {
  try {
    return npubEncode(hex);
  } catch (error) {
    logger.error({ error, hex }, "Failed to encode public key to npub");
    throw error;
  }
}

/**
 * Encodes a private key into nsec format
 * @param {string} hex - The hex-encoded private key
 * @returns {string} The bech32-encoded nsec string
 * @throws {Error} If encoding fails
 * @security This function handles sensitive private key data
 * @example
 * const nsec = hexToNsec('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
 * returns 'nsec1...'
 */
export function hexToNsec(hex: string): string {
  try {
    return nsecEncode(hex);
  } catch (error) {
    logger.error({ error }, "Failed to encode private key to nsec");
    throw error;
  }
}

/**
 * Encodes an event ID into note format
 * @param {string} hex - The hex-encoded event ID
 * @returns {string} The bech32-encoded note string
 * @throws {Error} If encoding fails
 * @example
 * const note = hexToNote('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
 * returns 'note1...'
 */
export function hexToNote(hex: string): string {
  try {
    return noteEncode(hex);
  } catch (error) {
    logger.error({ error, hex }, "Failed to encode event ID to note");
    throw error;
  }
}

/**
 * Decodes a bech32-encoded Nostr entity
 * @param {string} str - The bech32-encoded string (npub1, nsec1, or note1)
 * @returns {Nip19Data} Object containing the decoded type and data
 * @throws {Error} If decoding fails
 * @example
 * const result = decode('npub1...');
 * returns { type: 'npub', data: '...' }
 */
export function decode(str: string): { type: Nip19DataType; data: string } {
  try {
    return nip19Decode(str);
  } catch (error) {
    logger.error({ error }, "Failed to decode bech32 string");
    throw error;
  }
}

/**
 * Converts a bech32 nsec private key to hex format
 * @param {string} nsec - The bech32-encoded nsec private key
 * @returns {string} The hex-encoded private key
 * @throws {Error} If conversion fails or input is invalid
 * @security This function handles sensitive private key data
 * @example
 * const hex = nsecToHex('nsec1...');
 * returns '3bf0c63f...'
 */
export function nsecToHex(nsec: string): string {
  try {
    const decoded = decode(nsec);
    if (decoded.type !== "nsec") {
      throw new Error("Invalid nsec format");
    }
    return decoded.data;
  } catch (error) {
    logger.error({ error }, "Failed to convert nsec to hex");
    throw error;
  }
}

/**
 * Converts a bech32 npub public key to hex format
 * @param {string} npub - The bech32-encoded npub public key
 * @returns {string} The hex-encoded public key
 * @throws {Error} If conversion fails or input is invalid
 * @example
 * const hex = npubToHex('npub1...');
 * returns '3bf0c63f...'
 */
export function npubToHex(npub: string): string {
  try {
    const decoded = decode(npub);
    if (decoded.type !== "npub") {
      throw new Error(`Invalid npub format: ${npub}`);
    }
    return decoded.data;
  } catch (error) {
    logger.error({ error, npub }, "Failed to convert npub to hex");
    throw error;
  }
}
