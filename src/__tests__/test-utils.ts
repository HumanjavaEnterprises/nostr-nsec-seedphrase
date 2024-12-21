import { vi } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Mock implementation for secp256k1
const mockSecp256k1Implementation = {
  utils: {
    randomPrivateKey: () => {
      return new Uint8Array(32).fill(1);
    },
    sha256: async (message: Uint8Array) => {
      return new Uint8Array(32).fill(2);
    },
    precompute: (windowSize?: number, point?: Uint8Array) => {
      // Mock implementation
    },
    hmacSha256: async (key: Uint8Array, ...messages: Uint8Array[]) => {
      return new Uint8Array(32).fill(3);
    },
    hmacSha256Sync: (key: Uint8Array, ...messages: Uint8Array[]) => {
      return new Uint8Array(32).fill(3);
    },
    sha256Sync: (message: Uint8Array) => {
      return new Uint8Array(32).fill(2);
    }
  }
};

// Export the mock implementation for backward compatibility
export const mockSecp256k1 = mockSecp256k1Implementation;

// Test constants - single source of truth
export const TEST_CONSTANTS = {
  // Original test keys
  PRIVATE_KEY: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
  PUBLIC_KEY: "02e755ea8675f7a092ac4ae1f3c3e0ad6d82744d3da0f5f7049eaa5b0adc3ea543",
  BOB_PRIVATE_KEY: "14821f017f1363b79ff45fca1c2c9c51f94c8e38f0400620425e4f16a14d92ea",
  BOB_PUBLIC_KEY: "02a790fde3532565eadb3fe6d64085c8b0558b9d170d9ebf9399cc7de7cd9774af",
  ALICE_PRIVATE_KEY: "f8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
  ALICE_PUBLIC_KEY: "02e755ea8675f7a092ac4ae1f3c3e0ad6d82744d3da0f5f7049eaa5b0adc3ea544",
  
  // Seed phrases and mnemonics
  SEED_PHRASE: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  TEST_MNEMONIC: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  TEST_SEED: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
  
  // Test event
  TEST_EVENT: {
    id: "b9f5441eea2af66e14987c7c8b5a36c85f360fad86c0dca0c0e358d3e9d30a33",
    pubkey: "02e755ea8675f7a092ac4ae1f3c3e0ad6d82744d3da0f5f7049eaa5b0adc3ea543",
    created_at: 1671217665,
    kind: 1,
    tags: [],
    content: "Hello, Nostr!",
    sig: "c9f5441eea2af66e14987c7c8b5a36c85f360fad86c0dca0c0e358d3e9d30a33c9f5441eea2af66e14987c7c8b5a36c85f360fad86c0dca0c0e358d3e9d30a33"
  },

  // Mock crypto values
  MOCK_RANDOM_BYTES: new Uint8Array(32).fill(1),
  MOCK_SIGNATURE: new Uint8Array(64).fill(2),
  MOCK_SHARED_SECRET: new Uint8Array(32).fill(3)
};

// Mock secp256k1
vi.mock('@noble/secp256k1', () => ({
  getPublicKey: vi.fn((privKey: Uint8Array) => {
    return hexToBytes(TEST_CONSTANTS.PUBLIC_KEY);
  }),
  sign: vi.fn((msg: Uint8Array, privKey: Uint8Array) => {
    return TEST_CONSTANTS.MOCK_SIGNATURE;
  }),
  verify: vi.fn((sig: Uint8Array, msg: Uint8Array, pubKey: Uint8Array) => {
    return Promise.resolve(true);
  }),
  getSharedSecret: vi.fn((privKey: Uint8Array, pubKey: Uint8Array) => {
    return TEST_CONSTANTS.MOCK_SHARED_SECRET;
  }),
  utils: mockSecp256k1Implementation.utils
}));

// Helper function to set up HMAC for testing
export function setupHMAC() {
  vi.mock('@noble/hashes/hmac', () => ({
    hmac: vi.fn().mockImplementation((hash: any, key: Uint8Array, message: Uint8Array) => {
      return TEST_CONSTANTS.MOCK_SHARED_SECRET;
    })
  }));
}

// Helper function to calculate event ID consistently
export function calculateEventId() {
  return TEST_CONSTANTS.TEST_EVENT.id;
}
