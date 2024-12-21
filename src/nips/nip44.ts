import { randomBytes } from '@noble/hashes/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { bytesToHex } from '@noble/hashes/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { deriveKey } from '../crypto/encryption';
import { encrypt as encryptMessage, decrypt as decryptMessage } from '../crypto/encryption';
import { encryptWithPassword, decryptWithPassword } from '../crypto/encryption';
import { validatePrivateKey, validatePublicKey } from '../crypto/keys';
import { toCompressed, toRawX } from '../crypto/key-transforms';

/**
 * NIP-44: Encrypted Direct Messages v2
 * @see https://github.com/nostr-protocol/nips/blob/master/44.md
 */

/**
 * Generate a random 24-byte nonce
 */
function generateNonce(): Uint8Array {
  return randomBytes(24);
}

/**
 * Derive a shared secret for encryption/decryption
 */
function deriveSharedSecret(privateKey: string, publicKey: string): Uint8Array {
  // Validate keys
  if (!validatePrivateKey(privateKey)) {
    throw new Error('Invalid private key');
  }
  if (!validatePublicKey(publicKey)) {
    throw new Error('Invalid public key');
  }

  // Convert public key to compressed format and get raw x-coordinate
  const compressedPubKey = bytesToHex(toCompressed(publicKey));
  const rawPubKey = toRawX(compressedPubKey);

  const sharedPoint = secp256k1.getSharedSecret(privateKey, rawPubKey);
  // Ensure proper alignment by creating a new array
  const result = new Uint8Array(32);
  result.set(sharedPoint.slice(1));
  return result;
}

/**
 * Encrypt a message using NIP-44
 */
export async function encrypt(
  plaintext: string,
  privateKey: string,
  publicKey: string
): Promise<string> {
  try {
    // Convert public key to compressed format
    const compressedPubKey = bytesToHex(toCompressed(publicKey));
    return await encryptMessage(plaintext, privateKey, compressedPubKey);
  } catch (error: any) {
    throw new Error(`NIP-44 encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt a message using NIP-44
 */
export async function decrypt(
  message: string,
  privateKey: string,
  publicKey: string
): Promise<string> {
  try {
    // Convert public key to compressed format
    const compressedPubKey = bytesToHex(toCompressed(publicKey));
    return await decryptMessage(message, privateKey, compressedPubKey);
  } catch (error: any) {
    throw new Error(`NIP-44 decryption failed: ${error.message}`);
  }
}

// Re-export password-based encryption functions
export {
  encryptWithPassword,
  decryptWithPassword
};
