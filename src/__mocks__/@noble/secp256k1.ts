// Mock implementation of @noble/secp256k1 for testing
import { bytesToHex as originalBytesToHex, hexToBytes as originalHexToBytes } from "@noble/hashes/utils";
import { vi } from 'vitest';

function ensureUint8Array(input: Uint8Array | string): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (typeof input === 'string') return originalHexToBytes(input);
  throw new Error('Input must be Uint8Array or hex string');
}

// Mock signature creation with unified interface
const sign = vi.fn((
  message: Uint8Array | string,
  privateKey: Uint8Array | string
): Uint8Array => {
  const msgBytes = ensureUint8Array(message);
  const privKeyBytes = ensureUint8Array(privateKey);
  
  // Create a deterministic mock signature
  const signature = new Uint8Array(64).fill(1);
  return signature;
});

// Mock point multiplication
const getPublicKey = vi.fn((privateKey: Uint8Array | string): Uint8Array => {
  const privKeyBytes = ensureUint8Array(privateKey);
  
  // Create a deterministic mock public key
  const publicKey = new Uint8Array(32).fill(2);
  return publicKey;
});

// Mock signature verification
const verify = vi.fn((
  signature: Uint8Array | string,
  message: Uint8Array | string,
  publicKey: Uint8Array | string
): boolean => {
  try {
    const sigBytes = ensureUint8Array(signature);
    const msgBytes = ensureUint8Array(message);
    const pubKeyBytes = ensureUint8Array(publicKey);
    
    // Always return true for valid input sizes
    return sigBytes.length === 64 && msgBytes.length === 32 && pubKeyBytes.length === 32;
  } catch (error) {
    return false;
  }
});

// Mock Schnorr signature functions
const schnorr = {
  sign: vi.fn((message: Uint8Array | string, privateKey: Uint8Array | string): Uint8Array => {
    return sign(message, privateKey);
  }),
  verify: vi.fn((
    signature: Uint8Array | string,
    message: Uint8Array | string,
    publicKey: Uint8Array | string
  ): boolean => {
    return verify(signature, message, publicKey);
  })
};

// Export utility functions
const utils = {
  bytesToHex: originalBytesToHex,
  hexToBytes: originalHexToBytes,
  precompute: vi.fn(() => {}),
  sha256: vi.fn((message: Uint8Array) => new Uint8Array(32).fill(3)),
  isValidPrivateKey: vi.fn(() => true),
  isValidPublicKey: vi.fn(() => true),
  normPrivateKeyToScalar: vi.fn(() => BigInt(1)),
  randomPrivateKey: vi.fn(() => new Uint8Array(32).fill(5))
};

// Export Point class mock
class Point {
  constructor(x?: Uint8Array, y?: Uint8Array) {}
  static BASE = new Point();
  static fromHex(hex: string): Point {
    return new Point();
  }
  multiply(scalar: bigint | number | string): Point {
    return new Point();
  }
  toRawBytes(): Uint8Array {
    return new Uint8Array(32).fill(4);
  }
}

// Export everything as a default export
export default {
  getPublicKey,
  schnorr,
  utils,
  sign,
  verify,
  Point
};
