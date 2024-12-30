/**
 * NIP-19: bech32-encoded entities
 * @module nip19
 * @description Implements NIP-19 specification for bech32-encoded entities in Nostr.
 * Provides encoding and decoding functions for npub (public keys), nsec (private keys),
 * and note (event IDs) formats.
 * @see https://github.com/nostr-protocol/nips/blob/master/19.md
 */

import { bech32 } from '@scure/base';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { logger } from '../utils/logger.js';
import type { Bech32Result } from '../types/index.js';

/**
 * Valid bech32 prefix types for Nostr entities
 * @typedef {('npub1' | 'nsec1' | 'note1')} Bech32Prefix
 */
type Bech32Prefix = 'npub1' | 'nsec1' | 'note1';

/**
 * Ensures the input string has a valid bech32 format by adding '1' if missing
 * @param {string} str - Input string to format
 * @returns {string} Properly formatted bech32 string
 * @example
 * ensureBech32Format('npub') // returns 'npub1'
 * ensureBech32Format('npub1abc') // returns 'npub1abc'
 */
function ensureBech32Format(str: string): `${string}1${string}` {
  return str.includes('1') ? str as `${string}1${string}` : `${str}1`;
}

/**
 * Encodes a public key into npub format
 * @param {string} hex - The hex-encoded public key
 * @returns {string} The bech32-encoded npub string
 * @throws {Error} If encoding fails
 * @example
 * const npub = hexToNpub('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
 * // returns 'npub1...'
 */
export function hexToNpub(hex: string): string {
  try {
    const bytes = hexToBytes(hex);
    const words = bech32.toWords(bytes);
    const encoded = bech32.encode('npub1' as Bech32Prefix, words);
    return encoded;
  } catch (error) {
    logger.error('Failed to encode npub:', error);
    throw new Error('Failed to encode npub');
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
 * // returns 'nsec1...'
 */
export function hexToNsec(hex: string): string {
  try {
    const bytes = hexToBytes(hex);
    const words = bech32.toWords(bytes);
    const encoded = bech32.encode('nsec1' as Bech32Prefix, words);
    return encoded;
  } catch (error) {
    logger.error('Failed to encode nsec:', error);
    throw new Error('Failed to encode nsec');
  }
}

/**
 * Encodes an event ID into note format
 * @param {string} hex - The hex-encoded event ID
 * @returns {string} The bech32-encoded note string
 * @throws {Error} If encoding fails
 * @example
 * const note = hexToNote('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
 * // returns 'note1...'
 */
export function hexToNote(hex: string): string {
  try {
    const bytes = hexToBytes(hex);
    const words = bech32.toWords(bytes);
    const encoded = bech32.encode('note1' as Bech32Prefix, words);
    return encoded;
  } catch (error) {
    logger.error('Failed to encode note:', error);
    throw new Error('Failed to encode note');
  }
}

/**
 * Decodes a bech32-encoded Nostr entity
 * @param {string} str - The bech32-encoded string (npub1, nsec1, or note1)
 * @returns {Bech32Result} Object containing the decoded type and data
 * @throws {Error} If decoding fails
 * @example
 * const result = decode('npub1...');
 * // returns { type: 'npub', data: Uint8Array }
 */
export function decode(str: string): Bech32Result {
  try {
    const formattedStr = ensureBech32Format(str);
    const { prefix, words } = bech32.decode(formattedStr);
    const data = new Uint8Array(bech32.fromWords(words));
    return { type: prefix.replace(/1$/, ''), data };
  } catch (error) {
    logger.error('Failed to decode bech32:', error);
    throw new Error('Failed to decode bech32');
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
 * // returns '3bf0c63f...'
 */
export function nsecToHex(nsec: string): string {
  try {
    const { type, data } = decode(nsec);
    if (type !== 'nsec') {
      throw new Error('Invalid nsec format');
    }
    return bytesToHex(data);
  } catch (error) {
    logger.error('Failed to convert nsec to hex:', error);
    throw new Error('Failed to convert nsec to hex');
  }
}

/**
 * Converts a bech32 npub public key to hex format
 * @param {string} npub - The bech32-encoded npub public key
 * @returns {string} The hex-encoded public key
 * @throws {Error} If conversion fails or input is invalid
 * @example
 * const hex = npubToHex('npub1...');
 * // returns '3bf0c63f...'
 */
export function npubToHex(npub: string): string {
  try {
    const { type, data } = decode(npub);
    if (type !== 'npub') {
      throw new Error('Invalid npub format');
    }
    return bytesToHex(data);
  } catch (error) {
    logger.error('Failed to convert npub to hex:', error);
    throw new Error('Failed to convert npub to hex');
  }
}
