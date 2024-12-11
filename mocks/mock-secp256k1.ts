export const utils = {
    hmacSha256: (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
        // Mock implementation of HMAC SHA256
        const result = new Uint8Array(32); // Dummy result
        result.fill(1); // Fill with dummy data
        return result;
    },
    hmacSha256Sync: (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
        // Mock implementation of synchronous HMAC SHA256
        const result = new Uint8Array(32); // Dummy result
        result.fill(1); // Fill with dummy data
        return result;
    }
};
