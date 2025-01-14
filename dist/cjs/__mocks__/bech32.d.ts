declare function toWords(data: Uint8Array): number[];
declare function fromWords(words: number[]): number[];
declare function encode(prefix: string, words: number[], limit: number): string;
declare function decode(str: string, limit?: number): {
    prefix: string;
    words: number[];
};
export declare const bech32: {
    toWords: typeof toWords;
    fromWords: typeof fromWords;
    encode: typeof encode;
    decode: typeof decode;
};
export {};
