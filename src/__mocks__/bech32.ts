// Mock implementation of bech32 for testing
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

function toWords(data: Uint8Array): number[] {
  // Convert bytes to 5-bit words
  const words: number[] = [];
  for (let i = 0; i < data.length; i++) {
    words.push(data[i] & 0x1f); // Take the lower 5 bits
  }
  return words;
}

function fromWords(words: number[]): number[] {
  // Convert 5-bit words back to bytes
  // Return number[] to match real bech32 library behavior
  const data = new Uint8Array(words.length);
  for (let i = 0; i < words.length; i++) {
    data[i] = words[i] & 0xff;
  }
  return Array.from(data);
}

function encode(prefix: string, words: number[], limit: number): string {
  // Simple mock encoding: prefix1<hex>
  const data = Uint8Array.from(words);
  return `${prefix}1${bytesToHex(data)}`;
}

function decode(str: string, limit?: number): { prefix: string; words: number[] } {
  // Simple mock decoding: split on '1'
  const [prefix, data] = str.split('1');
  if (!prefix || !data) {
    throw new Error('Invalid bech32 string');
  }
  const bytes = hexToBytes(data);
  return {
    prefix,
    words: Array.from(bytes).map(b => b & 0x1f) // Convert to 5-bit words
  };
}

export const bech32 = {
  toWords,
  fromWords,
  encode,
  decode
};
