"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bech32 = void 0;
// Mock implementation of bech32 for testing
const utils_1 = require("@noble/hashes/utils");
function toWords(data) {
    // Convert bytes to 5-bit words
    const words = [];
    for (let i = 0; i < data.length; i++) {
        words.push(data[i] & 0x1f); // Take the lower 5 bits
    }
    return words;
}
function fromWords(words) {
    // Convert 5-bit words back to bytes
    // Return number[] to match real bech32 library behavior
    const data = new Uint8Array(words.length);
    for (let i = 0; i < words.length; i++) {
        data[i] = words[i] & 0xff;
    }
    return Array.from(data);
}
function encode(prefix, words, limit) {
    // Simple mock encoding: prefix1<hex>
    const data = Uint8Array.from(words);
    return `${prefix}1${(0, utils_1.bytesToHex)(data)}`;
}
function decode(str, limit) {
    // Simple mock decoding: split on '1'
    const [prefix, data] = str.split('1');
    if (!prefix || !data) {
        throw new Error('Invalid bech32 string');
    }
    const bytes = (0, utils_1.hexToBytes)(data);
    return {
        prefix,
        words: Array.from(bytes).map(b => b & 0x1f) // Convert to 5-bit words
    };
}
exports.bech32 = {
    toWords,
    fromWords,
    encode,
    decode
};
