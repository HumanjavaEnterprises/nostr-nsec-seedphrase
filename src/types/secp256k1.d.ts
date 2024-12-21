declare module '@noble/secp256k1' {
  type Hex = string | Uint8Array;
  type PrivKey = Hex | bigint;
  type PubKey = Hex | Point;

  class Point {
    constructor(x: bigint, y: bigint);
    static fromHex(hex: Hex): Point;
    toRawBytes(compressed?: boolean): Uint8Array;
    toHex(compressed?: boolean): string;
    multiply(scalar: bigint): Point;
    add(other: Point): Point;
    subtract(other: Point): Point;
    double(): Point;
    negate(): Point;
    multiplyUnsafe(scalar: bigint): Point;
    hasEvenY(): boolean;
  }

  // ProjectivePoint is the same as Point in newer versions
  type ProjectivePoint = Point;

  namespace utils {
    function normPrivateKeyToScalar(key: PrivKey): bigint;
    function isValidPrivateKey(key: Hex): boolean;
    function randomPrivateKey(): Uint8Array;
    function precompute(w?: number, p?: Point): Point;
    
    // Add hash function declarations
    let sha256Sync: (...messages: Uint8Array[]) => Uint8Array;
    let sha256Async: (...messages: Uint8Array[]) => Promise<Uint8Array>;
    
    // Add HMAC function declarations
    let hmacSha256Sync: (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;
    let hmacSha256Async: (key: Uint8Array, ...messages: Uint8Array[]) => Promise<Uint8Array>;
  }

  export { Point, ProjectivePoint, utils };
  export function getPublicKey(privateKey: PrivKey, compressed?: boolean): Uint8Array;
  export function sign(hash: Uint8Array, privateKey: PrivKey): Promise<{ toCompactRawBytes(): Uint8Array }>;
  export function verify(signature: Uint8Array, hash: Uint8Array, publicKey: PubKey): Promise<boolean>;
  export function getSharedSecret(privateKey: PrivKey, publicKey: PubKey): Uint8Array;
  export function schnorrSign(message: Uint8Array, privateKey: PrivKey): Promise<Uint8Array>;
  export function schnorrVerify(signature: Uint8Array, message: Uint8Array, publicKey: PubKey): Promise<boolean>;
}
