"use strict";
// WARNING: These keys are for testing purposes only!
// Never use these keys in production or for real Nostr events.
// They are intentionally hardcoded to ensure deterministic testing.
Object.defineProperty(exports, "__esModule", { value: true });
// Mock dependencies
vitest_1.vi.mock("@noble/secp256k1", () => {
    const TEST_PRIVATE_KEY = "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69";
    const TEST_PUBLIC_KEY = "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021";
    let lastSignedMessage = "";
    return {
        getPublicKey: () => new Uint8Array(hexToBytes(TEST_PUBLIC_KEY)),
        utils: {
            bytesToHex: (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''),
            hexToBytes: (hex) => new Uint8Array(hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []),
            isValidPrivateKey: () => true,
        },
        sign: (msg) => {
            lastSignedMessage = Array.from(msg).map(b => String.fromCharCode(b)).join('');
            return { toCompactRawBytes: () => new Uint8Array([1, 2, 3, 4]) };
        },
        verify: (sig, msg, pub) => {
            const msgStr = Array.from(msg).map(b => String.fromCharCode(b)).join('');
            return msgStr === lastSignedMessage;
        },
        Signature: {
            fromCompact: () => ({ toCompactRawBytes: () => new Uint8Array([1, 2, 3, 4]) })
        }
    };
});
vitest_1.vi.mock("bech32", () => ({
    bech32: {
        encode: (prefix, words) => prefix === "npub" ? "npub1test" : "nsec1test",
        decode: (str) => {
            const TEST_PRIVATE_KEY = "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69";
            const TEST_PUBLIC_KEY = "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021";
            if (str.startsWith("npub")) {
                return { prefix: "npub", words: Array.from(hexToBytes(TEST_PUBLIC_KEY)) };
            }
            else {
                return { prefix: "nsec", words: Array.from(hexToBytes(TEST_PRIVATE_KEY)) };
            }
        },
        toWords: (data) => Array.from(data),
        fromWords: (words) => new Uint8Array(words)
    }
}));
// Create a test Uint8Array for our mock
const testEntropy = new Uint8Array([
    39, 226, 160, 68, 100, 244, 231, 59, 145, 49, 84, 139, 109, 255, 190, 71,
    174, 73, 236, 122, 117, 98, 197, 161, 87, 230, 163, 15, 159, 28, 235, 105
]);
vitest_1.vi.mock("bip39", () => {
    return {
        validateMnemonic: (phrase) => phrase === "test test test test test test test test test test test junk",
        generateMnemonic: () => "test test test test test test test test test test test junk",
        mnemonicToEntropy: () => "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69"
    };
});
const vitest_1 = require("vitest");
const index_js_1 = require("../index.js");
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
(0, vitest_1.describe)("nostr-nsec-seedphrase", () => {
    (0, vitest_1.beforeAll)(() => {
        // Configure HMAC before running tests
        (0, index_js_1.configureHMAC)();
    });
    (0, vitest_1.beforeEach)(() => {
        // Clear all mocks before each test
        vitest_1.vi.clearAllMocks();
    });
    (0, vitest_1.describe)("Mocking Verification", () => {
        (0, vitest_1.it)("should properly mock bip39", () => {
            const result = (0, index_js_1.validateSeedPhrase)("test test test test test test test test test test test junk");
            console.log("Direct mock call result:", result);
            (0, vitest_1.expect)(result).toBe(true);
        });
    });
    (0, vitest_1.describe)("Key Generation", () => {
        (0, vitest_1.it)("should validate seed phrases", () => {
            const validResult = (0, index_js_1.validateSeedPhrase)("test test test test test test test test test test test junk");
            console.log("Valid seed phrase test result:", validResult);
            (0, vitest_1.expect)(validResult).toBe(true);
            const invalidResult = (0, index_js_1.validateSeedPhrase)("invalid seed phrase");
            console.log("Invalid seed phrase test result:", invalidResult);
            (0, vitest_1.expect)(invalidResult).toBe(false);
        });
        (0, vitest_1.it)("should generate a valid key pair with seed phrase", () => {
            const keyPair = (0, index_js_1.seedPhraseToKeyPair)("test test test test test test test test test test test junk");
            (0, vitest_1.expect)(keyPair.privateKey).toBeDefined();
            (0, vitest_1.expect)(keyPair.publicKey).toBeDefined();
            (0, vitest_1.expect)(keyPair.nsec).toMatch(/^nsec1/);
            (0, vitest_1.expect)(keyPair.npub).toMatch(/^npub1/);
            (0, vitest_1.expect)(keyPair.seedPhrase).toBe("test test test test test test test test test test test junk");
        });
        (0, vitest_1.it)("should convert seed phrase to key pair", () => {
            const keyPair = (0, index_js_1.seedPhraseToKeyPair)("test test test test test test test test test test test junk");
            (0, vitest_1.expect)(keyPair.privateKey).toBeDefined();
            (0, vitest_1.expect)(keyPair.publicKey).toBeDefined();
            (0, vitest_1.expect)(keyPair.nsec).toBeDefined();
            (0, vitest_1.expect)(keyPair.npub).toBeDefined();
        });
    });
    (0, vitest_1.describe)("Format Conversions", () => {
        (0, vitest_1.it)("should convert between hex and nsec/npub formats", () => {
            const keyPair = {
                privateKey: "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69",
                publicKey: "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
                nsec: "nsec1test",
                npub: "npub1test",
                seedPhrase: ""
            };
            // Test hex to nsec/npub
            const nsec = (0, index_js_1.hexToNsec)(keyPair.privateKey);
            const npub = (0, index_js_1.hexToNpub)(keyPair.publicKey);
            console.log("Converted nsec:", nsec);
            console.log("Converted npub:", npub);
            (0, vitest_1.expect)(nsec).toBe(keyPair.nsec);
            (0, vitest_1.expect)(npub).toBe(keyPair.npub);
            // Test nsec/npub to hex
            const privateKeyHex = (0, index_js_1.nsecToHex)(keyPair.nsec);
            const publicKeyHex = (0, index_js_1.npubToHex)(keyPair.npub);
            console.log("Converted private key hex:", privateKeyHex);
            console.log("Converted public key hex:", publicKeyHex);
            (0, vitest_1.expect)(privateKeyHex).toBe(keyPair.privateKey);
            (0, vitest_1.expect)(publicKeyHex).toBe(keyPair.publicKey);
        });
        (0, vitest_1.it)("should create key pair from hex", () => {
            const originalKeyPair = {
                privateKey: "27e2a04464f4e73b9131548b6dffbe47ae49ec7a7562c5a157e6a30f9f1ceb69",
                publicKey: "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
                nsec: "nsec1test",
                npub: "npub1test",
                seedPhrase: ""
            };
            const keyPair = (0, index_js_1.fromHex)(originalKeyPair.privateKey);
            console.log("Created key pair from hex:", keyPair);
            (0, vitest_1.expect)(keyPair.privateKey).toBe(originalKeyPair.privateKey);
            (0, vitest_1.expect)(keyPair.publicKey).toBe(originalKeyPair.publicKey);
            (0, vitest_1.expect)(keyPair.nsec).toBe(originalKeyPair.nsec);
            (0, vitest_1.expect)(keyPair.npub).toBe(originalKeyPair.npub);
        });
    });
    (0, vitest_1.describe)("Message Signing", () => {
        (0, vitest_1.it)("should sign and verify messages", async () => {
            const keyPair = (0, index_js_1.seedPhraseToKeyPair)("test test test test test test test test test test test junk");
            const message = "Hello, Nostr!";
            const signature = await (0, index_js_1.signMessage)(message, keyPair.privateKey);
            console.log("Generated signature:", signature);
            (0, vitest_1.expect)(signature).toBeDefined();
            const isValid = await (0, index_js_1.verifySignature)(message, signature, keyPair.publicKey);
            console.log("Verification result:", isValid);
            (0, vitest_1.expect)(isValid).toBe(true);
        });
        (0, vitest_1.it)("should fail verification for invalid signatures", async () => {
            const keyPair = (0, index_js_1.seedPhraseToKeyPair)("test test test test test test test test test test test junk");
            const message = "Hello, Nostr!";
            const wrongMessage = "Wrong message";
            const signature = await (0, index_js_1.signMessage)(message, keyPair.privateKey);
            const isValid = await (0, index_js_1.verifySignature)(wrongMessage, signature, keyPair.publicKey);
            console.log("Verification result for wrong message:", isValid);
            (0, vitest_1.expect)(isValid).toBe(false);
        });
    });
    (0, vitest_1.describe)("Event Handling", () => {
        (0, vitest_1.it)("should create and verify events", async () => {
            const keyPair = (0, index_js_1.seedPhraseToKeyPair)("test test test test test test test test test test test junk");
            const event = await (0, index_js_1.createEvent)("Hello, Nostr!", 1, keyPair.privateKey, [
                ["t", "test"],
            ]);
            console.log("Created event:", event);
            (0, vitest_1.expect)(event.pubkey).toBe(keyPair.publicKey);
            (0, vitest_1.expect)(event.kind).toBe(1);
            (0, vitest_1.expect)(event.content).toBe("Hello, Nostr!");
            (0, vitest_1.expect)(event.tags).toEqual([["t", "test"]]);
            (0, vitest_1.expect)(event.id).toBeDefined();
            (0, vitest_1.expect)(event.sig).toBeDefined();
            const isValid = await (0, index_js_1.verifyEvent)(event);
            console.log("Verification result:", isValid);
            (0, vitest_1.expect)(isValid).toBe(true);
        });
        (0, vitest_1.it)("should detect tampered events", async () => {
            const keyPair = (0, index_js_1.seedPhraseToKeyPair)("test test test test test test test test test test test junk");
            const event = await (0, index_js_1.createEvent)("Hello, Nostr!", 1, keyPair.privateKey);
            event.content = "Tampered content"; // Tamper with the content
            console.log("Event hash mismatch");
            const isValid = await (0, index_js_1.verifyEvent)(event);
            console.log("Verification result for tampered event:", isValid);
            (0, vitest_1.expect)(isValid).toBe(false);
        });
    });
    (0, vitest_1.describe)("HMAC Configuration", () => {
        (0, vitest_1.it)("should configure HMAC without errors", () => {
            (0, vitest_1.expect)(() => (0, index_js_1.configureHMAC)()).not.toThrow();
        });
    });
    (0, vitest_1.describe)("Random Key Generation", () => {
        (0, vitest_1.it)("should work with randomly generated keys", async () => {
            const keyPair = (0, index_js_1.generateKeyPairWithSeed)();
            // Test key format
            (0, vitest_1.expect)(keyPair.privateKey).toMatch(/^[0-9a-f]{64}$/);
            (0, vitest_1.expect)(keyPair.publicKey).toMatch(/^[0-9a-f]{64}$/);
            (0, vitest_1.expect)(keyPair.nsec).toMatch(/^nsec1/);
            (0, vitest_1.expect)(keyPair.npub).toMatch(/^npub1/);
            // Test signing with random keys
            const message = "Test message";
            const signature = await (0, index_js_1.signMessage)(message, keyPair.privateKey);
            const isValid = await (0, index_js_1.verifySignature)(message, signature, keyPair.publicKey);
            (0, vitest_1.expect)(isValid).toBe(true);
        });
    });
});
function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []);
}
