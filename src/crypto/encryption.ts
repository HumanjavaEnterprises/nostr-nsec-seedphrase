import { sha256 } from "@noble/hashes/sha256";
import * as secp256k1 from "@noble/secp256k1";
import { chacha20, chacha20poly1305 } from "@noble/ciphers/chacha";
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { validatePrivateKey, validatePublicKey } from "./keys";
import { randomBytes } from '@noble/hashes/utils';
import { hmac } from '@noble/hashes/hmac';
import { getPublicKey } from './keys';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

export class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EncryptionError';
  }
}

/**
 * Encrypt a message using shared secret derived from ECDH
 */
export async function encrypt(
  message: string,
  privateKey: string,
  publicKey: string
): Promise<string> {
  try {
    if (!message || !privateKey || !publicKey) {
      throw new Error('Missing required parameters');
    }

    // Validate keys
    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }
    if (!validatePublicKey(publicKey)) {
      throw new Error('Invalid public key');
    }

    // Convert keys to proper format
    const privKeyBytes = hexToBytes(privateKey);
    const pubKeyBytes = hexToBytes(publicKey);
    
    // Compute shared secret using ECDH
    const sharedPoint = secp256k1.getSharedSecret(privKeyBytes, pubKeyBytes);
    const sharedSecret = sha256(sharedPoint.slice(1));
    
    // Generate random IV
    const iv = randomBytes(16);
    
    // Encrypt the message
    const messageBytes = new TextEncoder().encode(message);
    const cipher = chacha20poly1305(sharedSecret, iv);
    const ciphertext = cipher.encrypt(messageBytes);
    
    // Combine IV and ciphertext
    const combined = new Uint8Array(iv.length + ciphertext.length);
    combined.set(iv);
    combined.set(ciphertext, iv.length);
    
    return bytesToHex(combined);
  } catch (error) {
    throw new EncryptionError(`Failed to encrypt message: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Decrypt a message using shared secret derived from ECDH
 */
export async function decrypt(
  encrypted: string,
  privateKey: string,
  publicKey: string
): Promise<string> {
  try {
    if (!encrypted || !privateKey || !publicKey) {
      throw new Error('Missing required parameters');
    }

    // Validate keys
    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }
    if (!validatePublicKey(publicKey)) {
      throw new Error('Invalid public key');
    }

    // Convert keys and encrypted data to bytes
    const privKeyBytes = hexToBytes(privateKey);
    const pubKeyBytes = hexToBytes(publicKey);
    const encryptedBytes = hexToBytes(encrypted);

    // Extract IV and ciphertext
    if (encryptedBytes.length < 16) {
      throw new Error('Invalid encrypted data');
    }
    const iv = encryptedBytes.slice(0, 16);
    const ciphertext = encryptedBytes.slice(16);

    // Compute shared secret using ECDH
    const sharedPoint = secp256k1.getSharedSecret(privKeyBytes, pubKeyBytes);
    const sharedSecret = sha256(sharedPoint.slice(1));

    // Decrypt the message
    const cipher = chacha20poly1305(sharedSecret, iv);
    const decrypted = cipher.decrypt(ciphertext);

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
  const _senderPubKey = getPublicKey(privateKey);
  return await encrypt(content, privateKey, recipientPubKey);
}

/**
 * Derive an encryption key from a password using PBKDF2
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array | null = null
): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  const useSalt = salt || randomBytes(16);
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);
  
  // Use PBKDF2 with SHA-256 for key derivation
  const key = pbkdf2(sha256, passwordBytes, useSalt, {
    c: 10000,  // Number of iterations
    dkLen: 32, // Output length in bytes
  });
  
  return { key, salt: useSalt };
}

/**
 * Encrypt a message with a password
 */
export async function encryptWithPassword(
  message: string,
  password: string
): Promise<{ ciphertext: Uint8Array; salt: Uint8Array; nonce: Uint8Array }> {
  const nonce = randomBytes(24);
  const { key, salt } = await deriveKey(password);
  
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(new TextEncoder().encode(message));
  
  return { ciphertext, salt, nonce };
}

/**
 * Decrypt a message with a password
 */
export async function decryptWithPassword(
  ciphertext: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  password: string
): Promise<string> {
  const { key } = await deriveKey(password, salt);
  const cipher = xchacha20poly1305(key, nonce);
  const plaintext = cipher.decrypt(ciphertext);
  
  const decoder = new TextDecoder('utf-8', { fatal: false });
  let decodedMessage = decoder.decode(plaintext);
  
  // Handle special characters and edge cases
  decodedMessage = decodedMessage.replace(/\uFFFD/g, ''); // Remove invalid characters
  decodedMessage = decodedMessage.trim(); // Remove leading and trailing whitespace

  return decodedMessage;
}
