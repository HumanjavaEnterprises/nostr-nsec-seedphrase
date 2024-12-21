import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { hmac } from "@noble/hashes/hmac";
import { UnsignedEvent } from "../types/events";

/**
 * Count the number of leading zero bits in a hex string
 * @param {string} hex - The hex string to check
 * @returns {number} The number of leading zero bits
 */
export function countLeadingZeroes(hex: string): number {
  let bits = 0;
  for (let i = 0; i < hex.length; i++) {
    const char = parseInt(hex[i], 16);
    if (char === 0) {
      bits += 4;
      continue;
    }
    // Count remaining bits in this character
    if (char < 2) bits++;
    else if (char < 4) bits += 2;
    else if (char < 8) bits += 3;
    break;
  }
  return bits;
}

/**
 * Calculate the number of leading zero bits in a hash
 * @param {Uint8Array} hash - The hash to check
 * @returns {number} The number of leading zero bits
 */
export function countLeadingZeroBits(hash: Uint8Array): number {
  let bits = 0;
  for (const byte of hash) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    // Count remaining bits in this byte
    if (byte < 2) bits++;
    else if (byte < 4) bits += 2;
    else if (byte < 8) bits += 3;
    else if (byte < 16) bits += 4;
    else if (byte < 32) bits += 5;
    else if (byte < 64) bits += 6;
    else if (byte < 128) bits += 7;
    break;
  }
  return bits;
}

/**
 * Calculate event ID without signing
 * @param {UnsignedEvent} event - The event to calculate ID for
 * @returns {string} The event ID
 */
export function calculateEventId(event: UnsignedEvent): string {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
  return bytesToHex(sha256(Buffer.from(serialized)));
}

/**
 * Calculate HMAC-SHA256 of a message
 * @param {Uint8Array} key - The key for HMAC
 * @param {Uint8Array} message - The message to hash
 * @returns {Uint8Array} The HMAC result
 */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(sha256, key, message);
}

/**
 * Calculate HMAC-SHA256 of a message asynchronously
 * @param {Uint8Array} key - The key for HMAC
 * @param {Uint8Array} message - The message to hash
 * @returns {Promise<Uint8Array>} The HMAC result
 */
export async function hmacSha256Async(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  return hmac(sha256, key, message);
}
