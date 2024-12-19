import { getPublicKey } from './keys';
import { randomBytes } from '@noble/hashes/utils';
import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { toHex, fromHex } from '../utils/encoding';
import { webcrypto } from 'node:crypto';
const crypto = webcrypto;

export class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EncryptionError';
  }
}

/**
 * Encrypt a message using shared secret
 * @param message - The message to encrypt
 * @param privateKey - The sender's private key
 * @param publicKey - The recipient's public key
 * @returns The encrypted message as a string
 */
export async function encrypt(
  message: string,
  privateKey: string,
  publicKey: string
): Promise<string> {
  try {
    // Generate 32 bytes of random data for the initialization vector
    const iv = randomBytes(16);  // AES-CBC requires exactly 16 bytes

    // Derive shared point and hash it for the encryption key
    const sharedPoint = secp256k1.getSharedSecret(privateKey, '02' + publicKey);
    const sharedX = sharedPoint.slice(1, 33);  // Remove prefix byte
    const encryptionKey = sha256(sharedX);

    // Import the key for use with WebCrypto
    const key = await crypto.subtle.importKey(
      'raw',
      encryptionKey,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt']
    );

    // Encrypt the message
    const encodedMessage = new TextEncoder().encode(message);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      key,
      encodedMessage
    );

    // Combine IV and ciphertext and encode as base64
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.length);
    
    return Buffer.from(combined).toString('base64');
  } catch (error) {
    throw new EncryptionError(`Failed to encrypt message: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Decrypt a message using shared secret
 * @param encrypted - The encrypted message
 * @param privateKey - The recipient's private key
 * @param publicKey - The sender's public key
 * @returns The decrypted message
 */
export async function decrypt(
  encrypted: string,
  privateKey: string,
  publicKey: string
): Promise<string> {
  try {
    // Decode the combined IV and ciphertext from base64
    const combined = Buffer.from(encrypted, 'base64');
    
    // Split IV and ciphertext
    const iv = combined.slice(0, 16);
    const ciphertext = combined.slice(16);

    // Derive shared point and hash it for the decryption key
    const sharedPoint = secp256k1.getSharedSecret(privateKey, '02' + publicKey);
    const sharedX = sharedPoint.slice(1, 33);  // Remove prefix byte
    const decryptionKey = sha256(sharedX);

    // Import the key for use with WebCrypto
    const key = await crypto.subtle.importKey(
      'raw',
      decryptionKey,
      { name: 'AES-CBC', length: 256 },
      false,
      ['decrypt']
    );

    // Decrypt the message
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      key,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    throw new EncryptionError(`Failed to decrypt message: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Create an encrypted message
 * @param content - The message content to encrypt
 * @param privateKey - The sender's private key
 * @param recipientPubKey - The recipient's public key
 * @returns The encrypted content
 */
export async function createEncryptedMessage(
  content: string,
  privateKey: string,
  recipientPubKey: string
): Promise<string> {
  const senderPubKey = getPublicKey(privateKey);
  return await encrypt(content, privateKey, recipientPubKey);
}

/**
 * Encrypt sensitive data with a password
 * @param data - The sensitive data to encrypt
 * @param password - Password to encrypt with
 * @returns Encrypted data in base64
 */
export async function encryptWithPassword(data: string, password: string): Promise<string> {
  const { key, salt } = await deriveKey(password);
  const iv = randomBytes(16);  // AES-CBC requires 16 bytes IV
  
  // Import the key for use with WebCrypto
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt']
  );

  // Encrypt the data
  const plaintext = new TextEncoder().encode(data);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    plaintext
  );
  
  // Combine salt, IV, and ciphertext
  const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
  combined.set(salt);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
  
  return Buffer.from(combined).toString('base64');
}

/**
 * Decrypt sensitive data with a password
 * @param encryptedData - The encrypted data in base64
 * @param password - Password to decrypt with
 * @returns Decrypted data
 */
export async function decryptWithPassword(encryptedData: string, password: string): Promise<string> {
  const combined = Buffer.from(encryptedData, 'base64');
  
  // Extract salt, IV, and ciphertext
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 32);
  const ciphertext = combined.slice(32);
  
  const { key } = await deriveKey(password, salt);
  
  // Import the key for use with WebCrypto
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC', length: 256 },
    false,
    ['decrypt']
  );
  
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      cryptoKey,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    throw new EncryptionError(`Failed to decrypt data: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Generate a secure encryption key from a password
 * @param password - Password to derive key from
 * @param salt - Optional salt (will be generated if not provided)
 * @returns Object containing the key and salt
 */
export async function deriveKey(password: string, salt?: Uint8Array): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  const useSalt = salt || randomBytes(16);
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  
  const key = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: useSalt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    passwordKey,
    256
  );
  
  return {
    key: new Uint8Array(key),
    salt: useSalt
  };
}
