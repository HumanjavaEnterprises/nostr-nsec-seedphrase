import * as secp256k1 from '@noble/secp256k1';
import { hexToBytes, bytesToHex } from '../utils/encoding';

export class KeyTransformError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyTransformError';
  }
}

/**
 * Validate a hex string public key format
 * @param pubKeyHex - The public key in hex format
 * @returns boolean indicating if the format is valid
 */
function isValidPubKeyHexFormat(pubKeyHex: string): boolean {
  // Remove '0x' prefix if present
  pubKeyHex = pubKeyHex.replace('0x', '');
  
  // Check if it's a valid compressed (33 bytes) or uncompressed (65 bytes) format
  const isValidLength = pubKeyHex.length === 66 || pubKeyHex.length === 130;
  const hasValidPrefix = pubKeyHex.match(/^(?:02|03|04)[0-9a-fA-F]+$/);
  
  return isValidLength && !!hasValidPrefix;
}

/**
 * Convert a public key to compressed format
 * @param publicKey - Public key in hex string or Uint8Array format
 * @returns Compressed public key as Uint8Array
 */
export function toCompressed(publicKey: string | Uint8Array): Uint8Array {
  try {
    let pubKeyBytes: Uint8Array;
    
    if (typeof publicKey === 'string') {
      if (!isValidPubKeyHexFormat(publicKey)) {
        throw new Error('Invalid public key format');
      }
      pubKeyBytes = hexToBytes(publicKey.replace('0x', ''));
    } else {
      if (publicKey.length !== 33 && publicKey.length !== 65) {
        throw new Error('Invalid public key length');
      }
      pubKeyBytes = publicKey;
    }
    
    // Parse the point and validate it's on the curve
    const point = secp256k1.Point.fromHex(bytesToHex(pubKeyBytes));
    if (!point.hasEvenY()) {
      point.negate();
    }
    return point.toRawBytes(true);
  } catch (error) {
    throw new KeyTransformError(`Failed to compress public key: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Extract the X coordinate from a public key
 * @param publicKey - Public key in hex string or Uint8Array format
 * @returns X coordinate as Uint8Array
 */
export function toRawX(publicKey: string | Uint8Array): Uint8Array {
  try {
    const compressed = toCompressed(publicKey);
    return compressed.slice(1); // Remove the prefix byte
  } catch (error) {
    throw new KeyTransformError(`Failed to extract X coordinate: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Convert a public key to uncompressed format
 * @param publicKey - Public key in hex string or Uint8Array format
 * @returns Uncompressed public key as Uint8Array
 */
export function toUncompressed(publicKey: string | Uint8Array): Uint8Array {
  try {
    let pubKeyBytes: Uint8Array;
    
    if (typeof publicKey === 'string') {
      if (!isValidPubKeyHexFormat(publicKey)) {
        throw new Error('Invalid public key format');
      }
      pubKeyBytes = hexToBytes(publicKey.replace('0x', ''));
    } else {
      if (publicKey.length !== 33 && publicKey.length !== 65) {
        throw new Error('Invalid public key length');
      }
      pubKeyBytes = publicKey;
    }
    
    // Parse the point and get uncompressed format
    const point = secp256k1.Point.fromHex(bytesToHex(pubKeyBytes));
    return point.toRawBytes(false);
  } catch (error) {
    throw new KeyTransformError(`Failed to uncompress public key: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Validate if a point is on the secp256k1 curve
 * @param publicKey - Public key in hex string or Uint8Array format
 * @returns boolean indicating if the point is on the curve
 */
export function isOnCurve(publicKey: string | Uint8Array): boolean {
  try {
    let pubKeyHex: string;
    if (typeof publicKey === 'string') {
      if (!isValidPubKeyHexFormat(publicKey)) {
        return false;
      }
      pubKeyHex = publicKey.replace('0x', '');
    } else {
      pubKeyHex = bytesToHex(publicKey);
    }
    
    // This will throw if the point is not on the curve
    secp256k1.Point.fromHex(pubKeyHex);
    return true;
  } catch {
    return false;
  }
}
