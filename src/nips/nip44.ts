import { randomBytes } from '@noble/hashes/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { sha256 } from '@noble/hashes/sha256';
import { getSharedSecret } from '../crypto/keys';
import { encryptWithPassword, decryptWithPassword, deriveKey } from '../crypto/encryption';

const NONCE_SIZE = 24;
const AUTH_TAG_SIZE = 16;
const VERSION_SIZE = 1;
const HEADER_SIZE = VERSION_SIZE + NONCE_SIZE;

/**
 * Encrypt a message using NIP-44 (v2 encrypted DMs)
 */
export function encrypt(
  plaintext: string,
  privateKey: string,
  publicKey: string
): string {
  // Generate a random nonce
  const nonce = randomBytes(NONCE_SIZE);
  
  // Get shared secret
  const sharedSecret = getSharedSecret(privateKey, publicKey);
  
  // Convert plaintext to Uint8Array
  const plaintextBytes = new TextEncoder().encode(plaintext);
  
  // Encrypt using XChaCha20-Poly1305
  const cipher = xchacha20poly1305(sharedSecret, nonce);
  const ciphertext = cipher.encrypt(plaintextBytes);
  
  // Combine version byte, nonce, and ciphertext
  const message = new Uint8Array(HEADER_SIZE + ciphertext.length);
  message[0] = 2;  // version 2
  message.set(nonce, VERSION_SIZE);
  message.set(ciphertext, HEADER_SIZE);
  
  return Buffer.from(message).toString('base64');
}

/**
 * Decrypt a message using NIP-44
 */
export function decrypt(
  encryptedMessage: string,
  privateKey: string,
  publicKey: string
): string {
  // Decode base64 message
  const message = Buffer.from(encryptedMessage, 'base64');
  
  // Extract version, nonce, and ciphertext
  const version = message[0];
  if (version !== 2) {
    throw new Error(`Unsupported version: ${version}`);
  }
  
  const nonce = message.slice(VERSION_SIZE, HEADER_SIZE);
  const ciphertext = message.slice(HEADER_SIZE);
  
  // Get shared secret
  const sharedSecret = getSharedSecret(privateKey, publicKey);
  
  // Decrypt using XChaCha20-Poly1305
  const cipher = xchacha20poly1305(sharedSecret, nonce);
  const plaintext = cipher.decrypt(ciphertext);
  
  return new TextDecoder().decode(plaintext);
}

// Re-export password-based encryption functions
export { 
  encryptWithPassword, 
  decryptWithPassword,
  deriveKey 
} from '../crypto/encryption';
