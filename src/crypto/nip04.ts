import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { validatePrivateKey, validatePublicKey, getPublicKey } from './keys';

/**
 * Encrypt a message using NIP-04 encryption
 * @param privateKey - The sender's private key
 * @param publicKey - The recipient's public key
 * @param text - The text to encrypt
 * @returns The encrypted message
 */
export async function encrypt(
  privateKey: string,
  publicKey: string,
  text: string
): Promise<string> {
  if (!validatePrivateKey(privateKey)) {
    throw new Error('Invalid private key');
  }
  if (!validatePublicKey(publicKey)) {
    throw new Error('Invalid public key');
  }

  const privKeyBytes = hexToBytes(privateKey);
  const pubKeyBytes = hexToBytes(publicKey);

  // Compute shared secret
  const sharedPoint = secp256k1.getSharedSecret(privKeyBytes, pubKeyBytes);
  const sharedX = sharedPoint.slice(1, 33);
  
  // Create initialization vector
  const iv = crypto.getRandomValues(new Uint8Array(16));
  
  // Import key
  const key = await crypto.subtle.importKey(
    'raw',
    sharedX,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt']
  );

  // Encrypt
  const textBytes = new TextEncoder().encode(text);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    key,
    textBytes
  );

  // Combine IV and ciphertext
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);

  return bytesToHex(combined);
}

/**
 * Decrypt a message using NIP-04 decryption
 * @param privateKey - The recipient's private key
 * @param publicKey - The sender's public key
 * @param encryptedText - The encrypted text (hex)
 * @returns The decrypted message
 */
export async function decrypt(
  privateKey: string,
  publicKey: string,
  encryptedText: string
): Promise<string> {
  if (!validatePrivateKey(privateKey)) {
    throw new Error('Invalid private key');
  }
  if (!validatePublicKey(publicKey)) {
    throw new Error('Invalid public key');
  }

  const privKeyBytes = hexToBytes(privateKey);
  const pubKeyBytes = hexToBytes(publicKey);
  const encryptedBytes = hexToBytes(encryptedText);

  // Extract IV and ciphertext
  const iv = encryptedBytes.slice(0, 16);
  const ciphertext = encryptedBytes.slice(16);

  // Compute shared secret
  const sharedPoint = secp256k1.getSharedSecret(privKeyBytes, pubKeyBytes);
  const sharedX = sharedPoint.slice(1, 33);

  // Import key
  const key = await crypto.subtle.importKey(
    'raw',
    sharedX,
    { name: 'AES-CBC', length: 256 },
    false,
    ['decrypt']
  );

  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}
