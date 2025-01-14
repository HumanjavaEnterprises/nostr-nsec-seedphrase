import { bytesToHex as originalBytesToHex, hexToBytes as originalHexToBytes } from "@noble/hashes/utils";
export declare function getPublicKey(privateKey: Uint8Array | string): Uint8Array;
export declare const schnorr: {
    sign(message: Uint8Array | string, privateKey: Uint8Array | string): Promise<Uint8Array>;
    verify(signature: Uint8Array | string, message: Uint8Array | string, publicKey: Uint8Array | string): Promise<boolean>;
};
export declare const utils: {
    bytesToHex: typeof originalBytesToHex;
    hexToBytes: typeof originalHexToBytes;
    isValidPrivateKey(key: Uint8Array | string): boolean;
    randomPrivateKey(): Uint8Array;
};
declare const _default: {
    getPublicKey: typeof getPublicKey;
    schnorr: {
        sign(message: Uint8Array | string, privateKey: Uint8Array | string): Promise<Uint8Array>;
        verify(signature: Uint8Array | string, message: Uint8Array | string, publicKey: Uint8Array | string): Promise<boolean>;
    };
    utils: {
        bytesToHex: typeof originalBytesToHex;
        hexToBytes: typeof originalHexToBytes;
        isValidPrivateKey(key: Uint8Array | string): boolean;
        randomPrivateKey(): Uint8Array;
    };
};
export default _default;
