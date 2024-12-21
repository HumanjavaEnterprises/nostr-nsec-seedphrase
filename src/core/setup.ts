import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as secp256k1 from '@noble/secp256k1';
import { hmacSha256, hmacSha256Async } from '../crypto/hashing';

// Set up HMAC for secp256k1 immediately
secp256k1.utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
  // Concatenate all messages
  const totalLength = messages.reduce((sum, msg) => sum + msg.length, 0);
  const combinedMessage = new Uint8Array(totalLength);
  let offset = 0;
  for (const msg of messages) {
    combinedMessage.set(msg, offset);
    offset += msg.length;
  }
  return hmacSha256(key, combinedMessage);
};

secp256k1.utils.hmacSha256Async = async (key: Uint8Array, ...messages: Uint8Array[]): Promise<Uint8Array> => {
  // Concatenate all messages
  const totalLength = messages.reduce((sum, msg) => sum + msg.length, 0);
  const combinedMessage = new Uint8Array(totalLength);
  let offset = 0;
  for (const msg of messages) {
    combinedMessage.set(msg, offset);
    offset += msg.length;
  }
  return hmacSha256Async(key, combinedMessage);
};

/**
 * Initialize cryptographic dependencies
 * Note: HMAC is already initialized at module load time above
 */
export function setupCrypto(): void {
  // Set randomBytes for proper key generation
  (secp256k1.utils as any).randomBytes = async (length: number): Promise<Uint8Array> => {
    const array = new Uint8Array(length);
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(array);
    } else {
      // Node.js
      const crypto = await import('crypto');
      const randomBytes = crypto.randomBytes(length);
      array.set(new Uint8Array(randomBytes.buffer));
    }
    return array;
  };
}

// Initialize remaining crypto setup
setupCrypto();
