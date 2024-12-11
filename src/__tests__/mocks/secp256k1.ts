import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";

// Mock secp256k1 implementation for testing
const mockSecp256k1 = {
  utils: {
    hmacSha256: (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
      const h = hmac.create(sha256, key);
      messages.forEach((msg) => h.update(msg));
      return h.digest();
    },
    hmacSha256Sync: (
      key: Uint8Array,
      ...messages: Uint8Array[]
    ): Uint8Array => {
      const h = hmac.create(sha256, key);
      messages.forEach((msg) => h.update(msg));
      return h.digest();
    },
  },
  // Add other necessary mock functions
  sign: async (message: Uint8Array, privateKey: Uint8Array): Promise<any> => {
    return {
      toCompactRawBytes: () => new Uint8Array(64).fill(1),
    };
  },
  verify: async (
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): Promise<boolean> => {
    return true;
  },
};

export default mockSecp256k1;
