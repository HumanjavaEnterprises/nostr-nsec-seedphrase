import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { vi } from 'vitest';
import { TEST_CONSTANTS } from './test-utils';

// Set up crypto for Node.js environment
if (!global.crypto) {
  import('crypto').then(crypto => {
    (global as any).crypto = crypto.webcrypto;
  });
}

// Initialize test environment
function initializeTestEnvironment() {
  // Set up deterministic randomness for testing
  const mockRandomBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    mockRandomBytes[i] = i + 1;
  }
  
  // Mock the crypto.getRandomValues function
  (global as any).crypto = {
    getRandomValues: (buffer: Uint8Array) => {
      buffer.set(mockRandomBytes.slice(0, buffer.length));
      return buffer;
    },
    // Add any other required crypto properties
    subtle: (global as any).crypto?.subtle
  };

  // Set up SHA-256 for secp256k1
  secp256k1.utils.sha256Sync = (...messages: Uint8Array[]): Uint8Array => {
    const h = sha256.create();
    messages.forEach(msg => h.update(msg));
    return h.digest();
  };

  // Set up HMAC-SHA256 for secp256k1
  secp256k1.utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
    const h = hmac.create(sha256, key);
    messages.forEach(msg => h.update(msg));
    return h.digest();
  };

  // Mock secp256k1 functions for testing
  vi.mock('@noble/secp256k1', () => ({
    getPublicKey: vi.fn((privKey: Uint8Array) => {
      // Return a deterministic public key for testing
      return new Uint8Array(32).fill(1);
    }),

    schnorr: {
      sign: vi.fn((msg: Uint8Array, privKey: Uint8Array) => {
        // Return a deterministic signature for testing
        return new Uint8Array(64).fill(2);
      }),

      verify: vi.fn((sig: Uint8Array, msg: Uint8Array, pubKey: Uint8Array) => {
        // Simple verification logic for testing
        return Promise.resolve(true);
      })
    },

    getSharedSecret: vi.fn((privKey: Uint8Array, pubKey: Uint8Array) => {
      // Return a deterministic shared secret for testing
      return new Uint8Array(32).fill(3);
    }),

    utils: {
      randomPrivateKey: () => {
        const privateKey = mockRandomBytes.slice(0, 32);
        if (!secp256k1.utils.isValidPrivateKey(privateKey)) {
          return hexToBytes(TEST_CONSTANTS.PRIVATE_KEY);
        }
        return privateKey;
      },
      sha256Sync: secp256k1.utils.sha256Sync,
      hmacSha256Sync: secp256k1.utils.hmacSha256Sync,
      isValidPrivateKey: secp256k1.utils.isValidPrivateKey,
      bytesToHex,
      hexToBytes
    }
  }));
}

// Initialize when the module loads
initializeTestEnvironment();

// Precompute for better performance
secp256k1.utils.precompute(8);
