import { scrypt } from '@noble/hashes/scrypt';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from 'crypto';
import { Buffer } from 'buffer';
import { bytesToHex, hexToBytes } from '../utils/encoding';

// Default encryption parameters
const DEFAULT_SCRYPT_PARAMS: ScryptParams = {
  N: 32768,  // 2^15
  r: 8,
  p: 1,
  dkLen: 32
};

interface ScryptParams {
  N: number;  // CPU/memory cost parameter
  r: number;  // Block size parameter
  p: number;  // Parallelization parameter
  dkLen?: number; // Derived key length
}

export function validateScryptParams(params: ScryptParams): boolean {
  if (!params) return false;
  
  // N must be a power of 2 and >= 16384 (2^14)
  if (!params.N || typeof params.N !== 'number' || params.N < 16384 || (params.N & (params.N - 1)) !== 0) {
    return false;
  }
  
  // r must be >= 8
  if (!params.r || typeof params.r !== 'number' || params.r < 8) {
    return false;
  }
  
  // p must be >= 1
  if (!params.p || typeof params.p !== 'number' || params.p < 1) {
    return false;
  }
  
  // dkLen must be >= 32 if specified
  if (params.dkLen !== undefined && (typeof params.dkLen !== 'number' || params.dkLen < 32)) {
    return false;
  }
  
  return true;
}

/**
 * Generate scrypt log parameters
 * Returns parameters for scrypt based on security requirements
 */
export function generateLogParams(): ScryptParams {
  return {
    N: DEFAULT_SCRYPT_PARAMS.N,
    r: DEFAULT_SCRYPT_PARAMS.r,
    p: DEFAULT_SCRYPT_PARAMS.p,
    dkLen: DEFAULT_SCRYPT_PARAMS.dkLen
  };
}

/**
 * Encrypt a private key using NIP-49
 */
export async function encryptPrivateKey(
  privateKey: string,
  password: string,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS
): Promise<string> {
  if (!privateKey || !password) {
    throw new Error('Private key and password are required');
  }

  if (!validateScryptParams(params)) {
    throw new Error('Invalid scrypt params');
  }

  try {
    // Generate salt
    const salt = randomBytes(16);
    
    // Derive encryption key using scrypt
    const key = scrypt(
      new TextEncoder().encode(password),
      salt,
      {
        N: params.N,
        r: params.r,
        p: params.p,
        dkLen: params.dkLen || 32
      }
    );

    // Generate nonce for XChaCha20-Poly1305
    const nonce = randomBytes(24);

    // Encrypt the private key
    const cipher = xchacha20poly1305(key, nonce);
    const ciphertext = cipher.encrypt(Buffer.from(privateKey, 'hex'));

    // Combine salt, nonce, and ciphertext
    const combined = new Uint8Array(salt.length + nonce.length + ciphertext.length);
    combined.set(salt);
    combined.set(nonce, salt.length);
    combined.set(ciphertext, salt.length + nonce.length);

    return Buffer.from(combined).toString('base64');
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to encrypt private key: ${error.message}`);
    }
    throw new Error('Failed to encrypt private key: Unknown error');
  }
}

/**
 * Decrypt a private key using NIP-49
 */
export async function decryptPrivateKey(
  encryptedKey: string,
  password: string,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS
): Promise<string> {
  if (!encryptedKey || !password) {
    throw new Error('Encrypted key and password are required');
  }

  if (!validateScryptParams(params)) {
    throw new Error('Invalid scrypt params');
  }

  try {
    const combined = Buffer.from(encryptedKey, 'base64');

    // Extract salt, nonce, and ciphertext
    const salt = combined.slice(0, 16);
    const nonce = combined.slice(16, 40);
    const ciphertext = combined.slice(40);

    // Derive decryption key using scrypt
    const key = scrypt(
      new TextEncoder().encode(password),
      salt,
      {
        N: params.N,
        r: params.r,
        p: params.p,
        dkLen: params.dkLen || 32
      }
    );

    // Decrypt the private key
    const cipher = xchacha20poly1305(key, nonce);
    const decrypted = cipher.decrypt(ciphertext);

    return Buffer.from(decrypted).toString('hex');
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to decrypt private key: ${error.message}`);
    }
    throw new Error('Failed to decrypt private key: Unknown error');
  }
}

/**
 * Validate an encrypted private key
 */
export async function validateEncryptedPrivateKey(
  encryptedKey: string,
  password: string
): Promise<boolean> {
  try {
    await decryptPrivateKey(encryptedKey, password);
    return true;
  } catch {
    return false;
  }
}

export {
  ScryptParams,
  DEFAULT_SCRYPT_PARAMS
};
