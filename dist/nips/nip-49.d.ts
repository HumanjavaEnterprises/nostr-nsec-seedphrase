/**
 * @module nips/nip-49
 * @description NIP-49 Private Key Encryption (ncryptsec) support
 * Converts between hex private keys and password-encrypted ncryptsec bech32 strings.
 * @see https://github.com/nostr-protocol/nips/blob/master/49.md
 */
/**
 * Encrypts a hex private key into an ncryptsec bech32 string
 * @param {string} privateKeyHex - The hex-encoded private key (64 hex chars / 32 bytes)
 * @param {string} password - The password to encrypt with
 * @param {number} [logn=16] - Scrypt log2(N) parameter (higher = slower but more secure)
 * @returns {string} The bech32-encoded ncryptsec string
 * @throws {Error} If encryption fails
 * @example
 * const ncryptsec = toNcryptsec("1234567890abcdef...", "my-strong-password");
 * console.log(ncryptsec); // "ncryptsec1..."
 */
export declare function toNcryptsec(privateKeyHex: string, password: string, logn?: number): string;
/**
 * Decrypts an ncryptsec bech32 string back to a hex private key
 * @param {string} ncryptsec - The bech32-encoded ncryptsec string
 * @param {string} password - The password used for encryption
 * @returns {string} The hex-encoded private key
 * @throws {Error} If decryption fails (wrong password, invalid format, etc.)
 * @example
 * const privateKeyHex = fromNcryptsec("ncryptsec1...", "my-strong-password");
 * console.log(privateKeyHex); // "1234567890abcdef..."
 */
export declare function fromNcryptsec(ncryptsec: string, password: string): string;
