import * as secp256k1 from "@noble/secp256k1";
import { toHex, fromHex } from "../utils/encoding";
import { randomBytes } from '@noble/hashes/utils';
import { ProjectivePoint } from '@noble/secp256k1';

export class KeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyError';
  }
}

/**
 * Generate a new private key
 * @returns A new private key as a hex string
 */
export function generatePrivateKey(): string {
  try {
    // Generate 32 bytes of random data for the private key
    const privateKeyBytes = randomBytes(32);
    
    // Ensure it's a valid private key
    if (!secp256k1.utils.isValidPrivateKey(privateKeyBytes)) {
      throw new Error('Generated invalid private key');
    }
    
    return toHex(privateKeyBytes);
  } catch (error) {
    throw new KeyError(`Failed to generate private key: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

export function getPublicKey(privateKey: string): string {
  try {
    if (!privateKey) {
      throw new Error('Private key is required');
    }
    return toHex(secp256k1.getPublicKey(privateKey));
  } catch (error) {
    throw new KeyError(`Failed to derive public key: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

export function validatePrivateKey(privateKey: string): boolean {
  try {
    if (!privateKey) return false;
    const keyBytes = fromHex(privateKey);
    return secp256k1.utils.isValidPrivateKey(keyBytes);
  } catch {
    return false;
  }
}

export function validatePublicKey(publicKey: string): boolean {
  try {
    if (!publicKey) return false;
    const keyBytes = fromHex(publicKey);
    
    // Try to parse the public key as a ProjectivePoint
    try {
      ProjectivePoint.fromHex(keyBytes);
      return true;
    } catch {
      return false;
    }
  } catch {
    return false;
  }
}

/**
 * Get a shared secret between two parties using ECDH
 * @param privateKey - Private key of party A
 * @param publicKey - Public key of party B
 * @returns The shared secret as a Uint8Array
 */
export function getSharedSecret(privateKey: string, publicKey: string): Uint8Array {
  try {
    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }
    if (!validatePublicKey(publicKey)) {
      throw new Error('Invalid public key');
    }

    const privateKeyBytes = fromHex(privateKey);
    const publicKeyBytes = fromHex(publicKey);
    return secp256k1.getSharedSecret(privateKeyBytes, publicKeyBytes);
  } catch (error) {
    throw new KeyError(`Failed to derive shared secret: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}