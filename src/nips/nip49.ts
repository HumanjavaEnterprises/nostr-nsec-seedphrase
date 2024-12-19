import { randomBytes, scrypt } from 'crypto';
import { createCipheriv, createDecipheriv } from 'crypto';
import { bytesToHex, hexToBytes } from '../utils/encoding';

// Default encryption parameters
const DEFAULT_SCRYPT_PARAMS = {
  N: 32768, // CPU/memory cost parameter (power of 2)
  r: 8,     // Block size parameter
  p: 1,     // Parallelization parameter
  dkLen: 32 // Derived key length
};

interface ScryptParams {
  N: number;
  r: number;
  p: number;
  dkLen: number;
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
  try {
    if (!privateKey || !password) {
      throw new Error('Private key and password are required');
    }

    // Generate salt and IV
    const salt = randomBytes(16);
    const iv = randomBytes(16);

    // Derive key using scrypt
    const key = await new Promise<Buffer>((resolve, reject) => {
      scrypt(password, salt, params.dkLen, params, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      });
    });

    // Create cipher and encrypt
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const privateKeyBytes = hexToBytes(privateKey);
    const encrypted = Buffer.concat([
      cipher.update(privateKeyBytes),
      cipher.final()
    ]);

    // Get auth tag
    const authTag = cipher.getAuthTag();

    // Combine all components
    const encryptedData = Buffer.concat([
      salt,
      iv,
      authTag,
      encrypted
    ]);

    return encryptedData.toString('base64');
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
  try {
    // Decode base64
    const encryptedData = Buffer.from(encryptedKey, 'base64');

    // Extract components
    const salt = encryptedData.slice(0, 16);
    const iv = encryptedData.slice(16, 32);
    const authTag = encryptedData.slice(32, 48);
    const encrypted = encryptedData.slice(48);

    // Derive key using scrypt
    const key = await new Promise<Buffer>((resolve, reject) => {
      scrypt(password, salt, params.dkLen, params, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      });
    });

    // Create decipher
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    // Decrypt
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);

    return bytesToHex(decrypted);
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
  password: string,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS
): Promise<boolean> {
  try {
    const decrypted = await decryptPrivateKey(encryptedKey, password, params);
    return decrypted.length === 64;
  } catch {
    return false;
  }
}

export {
  ScryptParams,
  DEFAULT_SCRYPT_PARAMS
};
