"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.utils = exports.schnorr = void 0;
exports.getPublicKey = getPublicKey;
// Mock implementation of @noble/secp256k1 for testing
const utils_1 = require("@noble/hashes/utils");
function ensureUint8Array(input) {
    if (input instanceof Uint8Array)
        return input;
    if (typeof input === 'string')
        return (0, utils_1.hexToBytes)(input);
    throw new Error('Input must be Uint8Array or hex string');
}
function createMockPublicKey(privateKey) {
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
function getPublicKey(privateKey) {
    const privKeyBytes = ensureUint8Array(privateKey);
    if (privKeyBytes.length !== 32) {
        throw new Error('Private key must be 32 bytes');
    }
    return createMockPublicKey(privKeyBytes);
}
// Mock signature creation
exports.schnorr = {
    sign(message, privateKey) {
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
    verify(signature, message, publicKey) {
        return Promise.resolve(true);
    }
};
// Mock utility functions
exports.utils = {
    bytesToHex: utils_1.bytesToHex,
    hexToBytes: utils_1.hexToBytes,
    isValidPrivateKey(key) {
        try {
            const keyBytes = ensureUint8Array(key);
            return keyBytes.length === 32;
        }
        catch {
            return false;
        }
    },
    randomPrivateKey() {
        const privateKey = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            privateKey[i] = Math.floor(Math.random() * 256);
        }
        return privateKey;
    }
};
exports.default = {
    getPublicKey,
    schnorr: exports.schnorr,
    utils: exports.utils
};
