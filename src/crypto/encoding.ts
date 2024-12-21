import { bech32 } from 'bech32';
import { EncodingError } from './errors';

export const PREFIXES = {
  NPUB: 'npub',
  NSEC: 'nsec',
  NOTE: 'note',
  NPROFILE: 'nprofile',
  NEVENT: 'nevent'
} as const;

export type NostrPrefix = typeof PREFIXES[keyof typeof PREFIXES];

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  if (!hex.match(/^[0-9a-fA-F]*$/)) {
    throw new EncodingError('Invalid hex string');
  }
  const normalized = hex.toLowerCase();
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Encode data to bech32 format
 */
export function encodeBech32(prefix: NostrPrefix, data: Uint8Array): string {
  try {
    const words = bech32.toWords(data);
    return bech32.encode(prefix, words);
  } catch (error) {
    throw new EncodingError(`Failed to encode bech32: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decode bech32 string
 */
export function decodeBech32(str: string): { prefix: NostrPrefix; data: Uint8Array } {
  try {
    const { prefix, words } = bech32.decode(str);
    const data = bech32.fromWords(words);
    return {
      prefix: prefix as NostrPrefix,
      data: new Uint8Array(data)
    };
  } catch (error) {
    throw new EncodingError(`Failed to decode bech32: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Convert hex to bech32 format
 */
export function hexToBech32(prefix: NostrPrefix, hex: string): string {
  try {
    const data = hexToBytes(hex);
    return encodeBech32(prefix, data);
  } catch (error) {
    throw new EncodingError(`Failed to convert hex to bech32: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Convert bech32 to hex format
 */
export function bech32ToHex(str: string): string {
  try {
    const { data } = decodeBech32(str);
    return bytesToHex(data);
  } catch (error) {
    throw new EncodingError(`Failed to convert bech32 to hex: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// NIP-19 convenience functions
export function hexToNpub(hex: string): string {
  if (hex.length !== 66) {
    throw new EncodingError('Invalid npub hex length');
  }
  return hexToBech32(PREFIXES.NPUB, hex);
}

export function hexToNsec(hex: string): string {
  if (hex.length !== 130) {
    throw new EncodingError('Invalid nsec hex length');
  }
  return hexToBech32(PREFIXES.NSEC, hex);
}

export function hexToNote(hex: string): string {
  if (hex.length !== 130) {
    throw new EncodingError('Invalid note hex length');
  }
  return hexToBech32(PREFIXES.NOTE, hex);
}

export function npubToHex(npub: string): string {
  if (!npub.startsWith(PREFIXES.NPUB)) {
    throw new EncodingError('Invalid npub string');
  }
  return bech32ToHex(npub);
}

export function nsecToHex(nsec: string): string {
  if (!nsec.startsWith(PREFIXES.NSEC)) {
    throw new EncodingError('Invalid nsec string');
  }
  return bech32ToHex(nsec);
}

export function noteToHex(note: string): string {
  if (!note.startsWith(PREFIXES.NOTE)) {
    throw new EncodingError('Invalid note string');
  }
  return bech32ToHex(note);
}

// Re-export EncodingError for convenience
export { EncodingError };
