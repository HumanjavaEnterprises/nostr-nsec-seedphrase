console.log("Loading secp256k1 mock");

let utilsValue = {
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

Object.defineProperty(exports, 'utils', {
    get: () => utilsValue,
    set: (value) => {
        utilsValue = { ...utilsValue, ...value };
    },
    configurable: true,
    enumerable: true
});

class Signature {
    constructor(private bytes: Uint8Array) {
        console.log("Creating Signature instance");
    }
    
    toCompactRawBytes(): Uint8Array {
        console.log("Calling toCompactRawBytes");
        return this.bytes;
    }
}

// Keep track of signed message hashes for verification
const signedHashes = new Map<string, boolean>();

export const sign = async (messageHash: Uint8Array, privateKey: Uint8Array): Promise<Signature> => {
    console.log("Calling mock sign function");
    const signatureBytes = new Uint8Array(64);
    signatureBytes.fill(1);
    // Store the message hash for verification
    const hashHex = Array.from(messageHash).map(b => b.toString(16).padStart(2, '0')).join('');
    signedHashes.set(hashHex, true);
    return new Signature(signatureBytes);
};

export const verify = async (signature: Uint8Array, messageHash: Uint8Array, publicKey: Uint8Array): Promise<boolean> => {
    const hashHex = Array.from(messageHash).map(b => b.toString(16).padStart(2, '0')).join('');
    return signedHashes.has(hashHex);
};
