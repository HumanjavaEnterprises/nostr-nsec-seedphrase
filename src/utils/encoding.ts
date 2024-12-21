import { TextEncoder, TextDecoder } from "util";
import { bytesToHex as nobleHexEncode, hexToBytes as nobleHexDecode } from "@noble/hashes/utils";
import { bech32 } from 'bech32';

export class EncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EncodingError';
  }
}

export const utf8Encoder = new TextEncoder();
export const utf8Decoder = new TextDecoder();

/**
 * Convert bytes to hex string
 */
export function toHex(bytes: Uint8Array): string {
  try {
    return nobleHexEncode(bytes);
  } catch (error) {
    if (error instanceof Error) {
      throw new EncodingError(`Failed to convert bytes to hex: ${error.message}`);
    }
    throw new EncodingError('Failed to convert bytes to hex: Unknown error');
  }
}

/**
 * Convert hex string to bytes
 */
export function fromHex(hex: string): Uint8Array {
  try {
    if (!hex.match(/^[0-9a-fA-F]*$/)) {
      throw new Error('Invalid hex string');
    }
    return nobleHexDecode(hex);
  } catch (error) {
    if (error instanceof Error) {
      throw new EncodingError(`Failed to convert hex to bytes: ${error.message}`);
    }
    throw new EncodingError('Failed to convert hex to bytes: Unknown error');
  }
}

/**
 * Convert string to bytes
 */
export function stringToBytes(str: string): Uint8Array {
  try {
    return utf8Encoder.encode(str);
  } catch (error) {
    if (error instanceof Error) {
      throw new EncodingError(`Failed to convert string to bytes: ${error.message}`);
    }
    throw new EncodingError('Failed to convert string to bytes: Unknown error');
  }
}

/**
 * Convert bytes to string
 */
export function bytesToString(bytes: Uint8Array): string {
  try {
    return utf8Decoder.decode(bytes);
  } catch (error) {
    if (error instanceof Error) {
      throw new EncodingError(`Failed to convert bytes to string: ${error.message}`);
    }
    throw new EncodingError('Failed to convert bytes to string: Unknown error');
  }
}

/**
 * Encode data to JSON string
 */
export function encodeJSON(data: unknown): string {
  try {
    return JSON.stringify(data);
  } catch (error) {
    if (error instanceof Error) {
      throw new EncodingError(`Failed to encode JSON: ${error.message}`);
    }
    throw new EncodingError('Failed to encode JSON: Unknown error');
  }
}

/**
 * Decode JSON string to data
 */
export function decodeJSON<T>(json: string): T {
  try {
    return JSON.parse(json) as T;
  } catch (error) {
    if (error instanceof Error) {
      throw new EncodingError(`Failed to decode JSON: ${error.message}`);
    }
    throw new EncodingError('Failed to decode JSON: Unknown error');
  }
}

/**
 * Convert bits from one base to another
 * @param {number[]} data - Input data as array of numbers
 * @param {number} fromBits - Source base (bits per number)
 * @param {number} toBits - Target base (bits per number)
 * @param {boolean} pad - Whether to pad the result
 * @returns {number[]} Converted data
 */
export function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const maxv = (1 << toBits) - 1;
  const result: number[] = [];

  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) {
      throw new Error('Invalid value for conversion');
    }
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >> bits) & maxv);
    }
  }

  if (pad) {
    if (bits > 0) {
      result.push((acc << (toBits - bits)) & maxv);
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error('Invalid padding');
  }

  return result;
}

// Constants for Nostr encodings
export const NPUB_PREFIX = 'npub';
export const NSEC_PREFIX = 'nsec';
export const NOTE_PREFIX = 'note';

/**
 * Encode a hex string to bech32 format
 */
export function bech32Encode(prefix: string, hex: string): string {
  if (!hex || typeof hex !== 'string') {
    throw new Error('Invalid hex string: must be a non-empty string');
  }

  // Normalize hex string
  hex = hex.toLowerCase();
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }

  if (!hex.match(/^[0-9a-f]+$/)) {
    throw new Error('Invalid hex string: contains non-hex characters');
  }

  if (prefix !== NPUB_PREFIX && prefix !== NSEC_PREFIX && prefix !== NOTE_PREFIX) {
    throw new Error(`Invalid prefix: ${prefix}. Must be one of: ${NPUB_PREFIX}, ${NSEC_PREFIX}, ${NOTE_PREFIX}`);
  }

  try {
    const data = fromHex(hex);
    const words = convertBits(Array.from(data), 8, 5, true);
    return bech32.encode(prefix, words, 1000);
  } catch (error) {
    throw new Error(`Failed to encode bech32: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Decode a bech32 string to hex
 */
export function bech32Decode(str: string): { type: string; data: string } {
  try {
    const { prefix, words } = bech32.decode(str, 1000);
    if (!words || words.length === 0) {
      throw new Error('Invalid bech32 string: no data');
    }

    const data = convertBits(words, 5, 8, false);
    if (!data || data.length === 0) {
      throw new Error('Invalid bech32 string: conversion failed');
    }

    return {
      type: prefix,
      data: toHex(new Uint8Array(data))
    };
  } catch (error) {
    throw new Error(`Failed to decode bech32: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

// Re-export noble hashes utilities
export { nobleHexEncode as bytesToHex, nobleHexDecode as hexToBytes };