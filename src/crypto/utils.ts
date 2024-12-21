import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex as nobleHexEncode, hexToBytes as nobleHexDecode } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from 'crypto';

// Re-export commonly used crypto utilities
export const crypto = secp256k1;

// Hex encoding/decoding
export { nobleHexEncode as bytesToHex, nobleHexDecode as hexToBytes };

// Hashing
export { sha256 };

/**
 * Generate cryptographically secure random bytes
 * @param length Number of bytes to generate
 * @returns Uint8Array of random bytes
 */
export function getRandomBytes(length: number): Uint8Array {
    return randomBytes(length);
}

/**
 * Generate a cryptographically secure random 32-byte private key
 * @returns Hex-encoded private key
 */
export function generatePrivateKey(): string {
    return nobleHexEncode(getRandomBytes(32));
}

/**
 * Derive public key from private key
 * @param privateKeyHex Hex-encoded private key
 * @returns Hex-encoded public key
 */
export function derivePublicKey(privateKeyHex: string): string {
    const privateKey = nobleHexDecode(privateKeyHex);
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    return nobleHexEncode(publicKey);
}
