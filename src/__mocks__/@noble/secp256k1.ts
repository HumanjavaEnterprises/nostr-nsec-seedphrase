// Mock implementation of @noble/secp256k1 for testing
import { bytesToHex as originalBytesToHex, hexToBytes as originalHexToBytes } from "@noble/hashes/utils";

function ensureUint8Array(input: Uint8Array | string): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (typeof input === 'string') return originalHexToBytes(input);
  throw new Error('Input must be Uint8Array or hex string');
}

function createMockPublicKey(privateKey: Uint8Array): Uint8Array {
  // Create a deterministic 33-byte compressed public key
  const mockPubKey = new Uint8Array(33);
  mockPubKey[0] = 0x02; // Compressed format prefix
  
  // Use private key to generate a deterministic public key
  for (let i = 0; i < 32; i++) {
    mockPubKey[i + 1] = privateKey[i] ^ 0x02; // XOR with 0x02 to make it different from private key
  }
  
  return mockPubKey;
}

// Mock point multiplication for public key derivation
export function getPublicKey(privateKey: Uint8Array | string): Uint8Array {
  const privKeyBytes = ensureUint8Array(privateKey);
  if (privKeyBytes.length !== 32) {
    throw new Error('Private key must be 32 bytes');
  }
  
  return createMockPublicKey(privKeyBytes);
}

// Mock signature creation
export const schnorr = {
  sign(message: Uint8Array | string, privateKey: Uint8Array | string): Promise<Uint8Array> {
    const msgBytes = ensureUint8Array(message);
    const privKeyBytes = ensureUint8Array(privateKey);
    const signature = new Uint8Array(64);
    
    // Create a deterministic signature
    for (let i = 0; i < 32; i++) {
      signature[i] = msgBytes[i % msgBytes.length];
      signature[i + 32] = privKeyBytes[i];
    }
    
    return Promise.resolve(signature);
  },
  
  verify(signature: Uint8Array | string, message: Uint8Array | string, publicKey: Uint8Array | string): Promise<boolean> {
    return Promise.resolve(true);
  }
};

// Mock utility functions
export const utils = {
  bytesToHex: originalBytesToHex,
  hexToBytes: originalHexToBytes,
  
  isValidPrivateKey(key: Uint8Array | string): boolean {
    try {
      const keyBytes = ensureUint8Array(key);
      return keyBytes.length === 32;
    } catch {
      return false;
    }
  },
  
  randomPrivateKey(): Uint8Array {
    const privateKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      privateKey[i] = Math.floor(Math.random() * 256);
    }
    return privateKey;
  }
};

export default {
  getPublicKey,
  schnorr,
  utils
};
