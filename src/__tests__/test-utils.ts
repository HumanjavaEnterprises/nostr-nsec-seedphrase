// WARNING: These keys are for testing purposes only!
// Never use these keys in production or for real Nostr events.
// They are intentionally hardcoded to ensure deterministic testing.

import { vi } from 'vitest';

export const TEST_CONSTANTS = {
  PRIVATE_KEY: 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
  PUBLIC_KEY: '0232f20e005e0fc0185a27f6ad704d312434491e64591e7b89140a4e0bcb8b606e',
  SEED_PHRASE: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  TEST_EVENT: {
    id: 'b9f5441eea2af66e14987c7c8b5a36c85f360fad86c0dca0c0e358d3e9d30a33',
    pubkey: '0232f20e005e0fc0185a27f6ad704d312434491e64591e7b89140a4e0bcb8b606e',
    created_at: 1671217665,
    kind: 1,
    tags: [],
    content: 'Hello, Nostr!',
    sig: 'c9f5441eea2af66e14987c7c8b5a36c85f360fad86c0dca0c0e358d3e9d30a33c9f5441eea2af66e14987c7c8b5a36c85f360fad86c0dca0c0e358d3e9d30a33'
  }
};

let lastSignedMessage = '';
let lastEncodedData = '';

// Mock secp256k1
export const mockSecp256k1 = () => {
  vi.mock('@noble/secp256k1', () => ({
    getPublicKey: (privateKey: Uint8Array) => {
      // Return a fixed public key for testing
      return new Uint8Array(Buffer.from(TEST_CONSTANTS.PUBLIC_KEY, 'hex'));
    },
    schnorr: {
      sign: async (msg: Uint8Array, privateKey: Uint8Array) => {
        lastSignedMessage = Array.from(msg).map(b => String.fromCharCode(b)).join('');
        console.log("Mock signing message:", lastSignedMessage);
        return new Uint8Array(64); // Return fixed signature for testing
      },
      verify: (sig: Uint8Array, msg: Uint8Array, _pub: Uint8Array) => {
        const msgStr = Array.from(msg).map(b => String.fromCharCode(b)).join('');
        console.log("Mock verifying signature for message:", msgStr);
        return msgStr === lastSignedMessage;
      },
    },
    utils: {
      bytesToHex: (bytes: Uint8Array) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''),
      hexToBytes: (hex: string) => new Uint8Array(hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []),
      randomBytes: (length: number) => new Uint8Array(length).fill(1), // Deterministic for testing
    }
  }));
};

// Mock bech32
export const mockBech32 = () => {
  vi.mock('bech32', () => ({
    bech32: {
      encode: (prefix: string, words: number[], limit?: number) => {
        lastEncodedData = words.join('');
        return `${prefix}1${words.map(w => w.toString(16).padStart(2, '0')).join('')}`;
      },
      decode: (str: string, limit?: number) => {
        const [prefix, data] = str.split('1');
        if (!prefix || !data) {
          throw new Error('Invalid bech32 string');
        }
        if (!['npub', 'nsec', 'note'].includes(prefix)) {
          throw new Error('Invalid prefix');
        }
        const words = data.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || [];
        return { prefix, words };
      },
      toWords: (bytes: Uint8Array) => Array.from(bytes),
      fromWords: (words: number[]) => new Uint8Array(words)
    }
  }));
};

// Mock bip39
export const mockBip39 = () => {
  vi.mock('bip39', () => ({
    generateMnemonic: () => TEST_CONSTANTS.SEED_PHRASE,
    validateMnemonic: (mnemonic: string) => mnemonic === TEST_CONSTANTS.SEED_PHRASE,
    mnemonicToSeed: async (mnemonic: string) => new Uint8Array(32).fill(1), // Fixed test seed
  }));
};
