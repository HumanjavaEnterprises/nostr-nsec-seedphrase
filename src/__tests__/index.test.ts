// WARNING: These keys are for testing purposes only!
// Never use these keys in production or for real Nostr events.
// They are intentionally hardcoded to ensure deterministic testing.

// Mock dependencies
vi.mock("@noble/secp256k1", () => {
  const TEST_PRIVATE_KEY = "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69";
  const TEST_PUBLIC_KEY = "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021";
  let lastSignedMessage = "";
  
  return {
    getPublicKey: () => new Uint8Array(hexToBytes(TEST_PUBLIC_KEY)),
    utils: {
      bytesToHex: (bytes: Uint8Array) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''),
      hexToBytes: (hex: string) => new Uint8Array(hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []),
      isValidPrivateKey: () => true,
    },
    sign: (msg: Uint8Array) => {
      lastSignedMessage = Array.from(msg).map(b => String.fromCharCode(b)).join('');
      return { toCompactRawBytes: () => new Uint8Array([1, 2, 3, 4]) };
    },
    verify: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => {
      const msgStr = Array.from(msg).map(b => String.fromCharCode(b)).join('');
      return msgStr === lastSignedMessage;
    },
    Signature: {
      fromCompact: () => ({ toCompactRawBytes: () => new Uint8Array([1, 2, 3, 4]) })
    }
  };
});

vi.mock("bech32", () => ({
  bech32: {
    encode: (prefix: string, words: number[]) => prefix === "npub" ? "npub1test" : "nsec1test",
    decode: (str: string) => {
      const TEST_PRIVATE_KEY = "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69";
      const TEST_PUBLIC_KEY = "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021";
      if (str.startsWith("npub")) {
        return { prefix: "npub", words: Array.from(hexToBytes(TEST_PUBLIC_KEY)) };
      } else {
        return { prefix: "nsec", words: Array.from(hexToBytes(TEST_PRIVATE_KEY)) };
      }
    },
    toWords: (data: Uint8Array) => Array.from(data),
    fromWords: (words: number[]) => new Uint8Array(words)
  }
}));

// Create a test Uint8Array for our mock
const testEntropy = new Uint8Array([
  39, 226, 160, 68, 100, 244, 231, 59, 145, 49, 84, 139, 109, 255, 190, 71,
  174, 73, 236, 122, 117, 98, 197, 161, 87, 230, 163, 15, 159, 28, 235, 105
]);

vi.mock("bip39", () => {
  return {
    validateMnemonic: (phrase: string) => phrase === "test test test test test test test test test test test junk",
    generateMnemonic: () => "test test test test test test test test test test test junk",
    mnemonicToEntropy: () => "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69"
  };
});

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import {
  generateKeyPairWithSeed,
  seedPhraseToKeyPair,
  validateSeedPhrase,
  nsecToHex,
  npubToHex,
  hexToNsec,
  hexToNpub,
  signMessage,
  verifySignature,
  createEvent,
  verifyEvent,
  configureHMAC,
  fromHex,
} from "../index.js";

/**
 * Tests for the nostr-nsec-seedphrase library.
 *
 * This suite covers:
 * - BIP39 seed phrase validation
 * - Key format conversions (hex ↔ nsec/npub)
 * - Message signing and verification
 * - Event creation and verification
 * - HMAC configuration
 * - Random key generation
 *
 * @version 0.5.0
 */
describe("nostr-nsec-seedphrase", () => {
  beforeAll(() => {
    // Configure HMAC before running tests
    configureHMAC();
  });

  beforeEach(() => {
    // Clear all mocks before each test
    vi.clearAllMocks();
  });

  describe("Mocking Verification", () => {
    it("should properly mock bip39", () => {
      const result = validateSeedPhrase("test test test test test test test test test test test junk");
      console.log("Direct mock call result:", result);
      expect(result).toBe(true);
    });
  });

  describe("Key Generation", () => {
    it("should validate seed phrases", () => {
      const validResult = validateSeedPhrase("test test test test test test test test test test test junk");
      console.log("Valid seed phrase test result:", validResult);
      expect(validResult).toBe(true);

      const invalidResult = validateSeedPhrase("invalid seed phrase");
      console.log("Invalid seed phrase test result:", invalidResult);
      expect(invalidResult).toBe(false);
    });

    it("should generate a valid key pair with seed phrase", () => {
      const keyPair = seedPhraseToKeyPair("test test test test test test test test test test test junk");
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.nsec).toMatch(/^nsec1/);
      expect(keyPair.npub).toMatch(/^npub1/);
      expect(keyPair.seedPhrase).toBe("test test test test test test test test test test test junk");
    });

    it("should convert seed phrase to key pair", () => {
      const keyPair = seedPhraseToKeyPair("test test test test test test test test test test test junk");
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.nsec).toBeDefined();
      expect(keyPair.npub).toBeDefined();
    });
  });

  describe("Format Conversions", () => {
    it("should convert between hex and nsec/npub formats", () => {
      const keyPair = { 
        privateKey: "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69",
        publicKey: "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
        nsec: "nsec1test",
        npub: "npub1test",
        seedPhrase: ""
      };

      // Test hex to nsec/npub
      const nsec = hexToNsec(keyPair.privateKey);
      const npub = hexToNpub(keyPair.publicKey);
      console.log("Converted nsec:", nsec);
      console.log("Converted npub:", npub);
      expect(nsec).toBe(keyPair.nsec);
      expect(npub).toBe(keyPair.npub);

      // Test nsec/npub to hex
      const privateKeyHex = nsecToHex(keyPair.nsec);
      const publicKeyHex = npubToHex(keyPair.npub);
      console.log("Converted private key hex:", privateKeyHex);
      console.log("Converted public key hex:", publicKeyHex);
      expect(privateKeyHex).toBe(keyPair.privateKey);
      expect(publicKeyHex).toBe(keyPair.publicKey);
    });

    it("should create key pair from hex", () => {
      const originalKeyPair = { 
        privateKey: "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69",
        publicKey: "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
        nsec: "nsec1test",
        npub: "npub1test",
        seedPhrase: ""
      };
      const keyPair = fromHex(originalKeyPair.privateKey);
      console.log("Created key pair from hex:", keyPair);
      expect(keyPair.privateKey).toBe(originalKeyPair.privateKey);
      expect(keyPair.publicKey).toBe(originalKeyPair.publicKey);
      expect(keyPair.nsec).toBe(originalKeyPair.nsec);
      expect(keyPair.npub).toBe(originalKeyPair.npub);
    });
  });

  describe("Message Signing", () => {
    it("should sign and verify messages", async () => {
      const keyPair = seedPhraseToKeyPair("test test test test test test test test test test test junk");
      const message = "Hello, Nostr!";

      const signature = await signMessage(message, keyPair.privateKey);
      console.log("Generated signature:", signature);
      expect(signature).toBeDefined();

      const isValid = await verifySignature(message, signature, keyPair.publicKey);
      console.log("Verification result:", isValid);
      expect(isValid).toBe(true);
    });

    it("should fail verification for invalid signatures", async () => {
      const keyPair = seedPhraseToKeyPair("test test test test test test test test test test test junk");
      const message = "Hello, Nostr!";
      const wrongMessage = "Wrong message";

      const signature = await signMessage(message, keyPair.privateKey);
      const isValid = await verifySignature(wrongMessage, signature, keyPair.publicKey);
      console.log("Verification result for wrong message:", isValid);
      expect(isValid).toBe(false);
    });
  });

  describe("Event Handling", () => {
    it("should create and verify events", async () => {
      const keyPair = seedPhraseToKeyPair("test test test test test test test test test test test junk");
      const event = await createEvent("Hello, Nostr!", 1, keyPair.privateKey, [
        ["t", "test"],
      ]);

      console.log("Created event:", event);
      expect(event.pubkey).toBe(keyPair.publicKey);
      expect(event.kind).toBe(1);
      expect(event.content).toBe("Hello, Nostr!");
      expect(event.tags).toEqual([["t", "test"]]);
      expect(event.id).toBeDefined();
      expect(event.sig).toBeDefined();

      const isValid = await verifyEvent(event);
      console.log("Verification result:", isValid);
      expect(isValid).toBe(true);
    });

    it("should detect tampered events", async () => {
      const keyPair = seedPhraseToKeyPair("test test test test test test test test test test test junk");
      const event = await createEvent("Hello, Nostr!", 1, keyPair.privateKey);
      event.content = "Tampered content"; // Tamper with the content
      console.log("Event hash mismatch");
      const isValid = await verifyEvent(event);
      console.log("Verification result for tampered event:", isValid);
      expect(isValid).toBe(false);
    });
  });

  describe("HMAC Configuration", () => {
    it("should configure HMAC without errors", () => {
      expect(() => configureHMAC()).not.toThrow();
    });
  });

  describe("Random Key Generation", () => {
    it("should work with randomly generated keys", async () => {
      const keyPair = generateKeyPairWithSeed();
      
      // Test key format
      expect(keyPair.privateKey).toMatch(/^[0-9a-f]{64}$/);
      expect(keyPair.publicKey).toMatch(/^[0-9a-f]{64}$/);
      expect(keyPair.nsec).toMatch(/^nsec1/);
      expect(keyPair.npub).toMatch(/^npub1/);
      
      // Test signing with random keys
      const message = "Test message";
      const signature = await signMessage(message, keyPair.privateKey);
      const isValid = await verifySignature(message, signature, keyPair.publicKey);
      expect(isValid).toBe(true);
    });
  });
});

function hexToBytes(hex: string) {
  return new Uint8Array(hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []);
}
