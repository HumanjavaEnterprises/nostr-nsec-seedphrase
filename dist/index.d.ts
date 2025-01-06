/**
 * Represents a Nostr key pair with associated formats
 * @interface
 */
export interface KeyPair {
    /** Private key in hex format */
    privateKey: string;
    /** Public key in hex format */
    publicKey: string;
    /** Private key in bech32 nsec format */
    nsec: string;
    /** Public key in bech32 npub format */
    npub: string;
    /** BIP39 seed phrase used to generate this key pair */
    seedPhrase: string;
}
/**
 * Represents a signed Nostr event
 * @interface
 * @see https://github.com/nostr-protocol/nips/blob/master/01.md
 */
export interface NostrEvent {
    /** Event ID (32-bytes lowercase hex of the sha256 of the serialized event data) */
    id: string;
    /** Event creator's public key (32-bytes lowercase hex) */
    pubkey: string;
    /** Unix timestamp in seconds */
    created_at: number;
    /** Event kind (integer) */
    kind: number;
    /** Array of arrays of strings (event tags) */
    tags: string[][];
    /** Event content (arbitrary string) */
    content: string;
    /** Event signature (64-bytes hex of the schnorr signature of the sha256 hash of the serialized event data) */
    sig: string;
}
/**
 * Represents an unsigned Nostr event before signing
 * @interface
 */
export interface UnsignedEvent {
    /** Event creator's public key (32-bytes lowercase hex) */
    pubkey: string;
    /** Unix timestamp in seconds */
    created_at: number;
    /** Event kind (integer) */
    kind: number;
    /** Array of arrays of strings (event tags) */
    tags: string[][];
    /** Event content (arbitrary string) */
    content: string;
}
/**
 * Generates a new BIP39 seed phrase
 * @returns {string} A random 12-word BIP39 mnemonic seed phrase
 * @example
 * const seedPhrase = generateSeedPhrase();
 * console.log(seedPhrase); // "witch collapse practice feed shame open despair creek road again ice least"
 */
export declare function generateSeedPhrase(): string;
/**
 * Converts a BIP39 seed phrase to its entropy value
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {Uint8Array} The entropy value
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const entropy = getEntropyFromSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(entropy); // Uint8Array
 */
export declare function getEntropyFromSeedPhrase(seedPhrase: string): Uint8Array;
/**
 * Validates a BIP39 seed phrase
 * @param {string} seedPhrase - The seed phrase to validate
 * @returns {boolean} True if the seed phrase is valid, false otherwise
 * @example
 * const isValid = validateSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(isValid); // true
 */
export declare function validateSeedPhrase(seedPhrase: string): boolean;
/**
 * Converts a BIP39 seed phrase to a Nostr key pair
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 * @example
 * const keyPair = seedPhraseToKeyPair("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(keyPair.privateKey); // hex private key
 * console.log(keyPair.publicKey);  // hex public key
 * console.log(keyPair.nsec);       // bech32 nsec private key
 * console.log(keyPair.npub);       // bech32 npub public key
 */
export declare function seedPhraseToKeyPair(seedPhrase: string): KeyPair;
/**
 * Generates a new key pair with a random seed phrase
 * @returns {KeyPair} A new key pair containing private and public keys in various formats
 * @example
 * const keyPair = generateKeyPairWithSeed();
 * console.log(keyPair.seedPhrase); // random seed phrase
 * console.log(keyPair.privateKey);  // hex private key
 * console.log(keyPair.publicKey);   // hex public key
 */
export declare function generateKeyPairWithSeed(): KeyPair;
/**
 * Creates a key pair from a hex private key
 * @param {string} privateKeyHex - The hex-encoded private key
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the private key is invalid
 * @example
 * const keyPair = fromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
 * console.log(keyPair.publicKey); // corresponding public key
 * console.log(keyPair.nsec);      // bech32 nsec private key
 * console.log(keyPair.npub);      // bech32 npub public key
 */
export declare function fromHex(privateKeyHex: string): KeyPair;
/**
 * Derives a public key from a private key
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The hex-encoded public key
 * @example
 * const pubkey = getPublicKey("1234567890abcdef...");
 * console.log(pubkey); // hex public key
 */
export declare function getPublicKey(privateKey: string): string;
/**
 * NIP-19 encoding and decoding functions
 * @namespace
 */
export declare const nip19: {
    /**
     * Encodes a public key into npub format
     * @param {string} pubkey - The hex-encoded public key
     * @returns {string} The bech32-encoded npub string
     */
    npubEncode(pubkey: string): string;
    /**
     * Decodes an npub string to hex format
     * @param {string} npub - The bech32-encoded npub string
     * @returns {string} The hex-encoded public key
     */
    npubDecode(npub: string): string;
    /**
     * Encodes a private key into nsec format
     * @param {string} privkey - The hex-encoded private key
     * @returns {string} The bech32-encoded nsec string
     */
    nsecEncode(privkey: string): string;
    /**
     * Decodes an nsec string to hex format
     * @param {string} nsec - The bech32-encoded nsec string
     * @returns {string} The hex-encoded private key
     */
    nsecDecode(nsec: string): string;
    /**
     * Encodes an event ID into note format
     * @param {string} eventId - The hex-encoded event ID
     * @returns {string} The bech32-encoded note string
     */
    noteEncode(eventId: string): string;
    /**
     * Decodes a note string to hex format
     * @param {string} note - The bech32-encoded note string
     * @returns {string} The hex-encoded event ID
     */
    noteDecode(note: string): string;
    /**
     * Decodes any bech32-encoded Nostr entity
     * @param {string} bech32str - The bech32-encoded string
     * @returns {{ type: string; data: Uint8Array }} Object containing the decoded type and data
     * @property {string} type - The type of the decoded entity (npub, nsec, or note)
     * @property {Uint8Array} data - The raw decoded data
     */
    decode(bech32str: string): {
        type: string;
        data: Uint8Array;
    };
};
/**
 * Signs a Nostr event
 * @param {UnsignedEvent} event - The event to sign
 * @param {string} privateKey - The hex-encoded private key to sign with
 * @returns {Promise<string>} The hex-encoded signature
 * @throws {Error} If signing fails
 * @example
 * const signature = await signEvent({
 *   pubkey: "...",
 *   created_at: Math.floor(Date.now() / 1000),
 *   kind: 1,
 *   tags: [],
 *   content: "Hello Nostr!"
 * }, privateKey);
 */
export declare function signEvent(event: UnsignedEvent, privateKey: string): Promise<string>;
/**
 * Verifies a Nostr event signature
 * @param {NostrEvent} event - The event to verify
 * @returns {Promise<boolean>} True if the signature is valid, false otherwise
 * @example
 * const isValid = await verifyEvent(event);
 * console.log(isValid); // true or false
 */
export declare function verifyEvent(event: NostrEvent): Promise<boolean>;
/**
 * Configures secp256k1 with HMAC for WebSocket utilities
 * This is required for some WebSocket implementations
 * @example
 * configureHMAC();
 */
export declare function configureHMAC(): void;
/**
 * Creates a new signed Nostr event
 * @param {string} content - The event content
 * @param {number} kind - The event kind (1 for text note, etc.)
 * @param {string} privateKey - The hex-encoded private key to sign with
 * @param {string[][]} [tags=[]] - Optional event tags
 * @returns {Promise<NostrEvent>} The signed event
 * @throws {Error} If event creation or signing fails
 * @example
 * const event = await createEvent(
 *   "Hello Nostr!",
 *   1,
 *   privateKey,
 *   [["t", "nostr"]]
 * );
 * console.log(event); // complete signed event
 */
export declare function createEvent(content: string, kind: number, privateKey: string, tags?: string[][]): Promise<NostrEvent>;
/**
 * Converts a BIP39 seed phrase to a private key
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const privateKey = seedPhraseToPrivateKey("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(privateKey); // hex private key
 */
export declare function seedPhraseToPrivateKey(seedPhrase: string): string;
/**
 * Converts a private key to bech32 nsec format
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The bech32-encoded nsec private key
 * @throws {Error} If the private key is invalid
 * @example
 * const nsec = privateKeyToNsec("1234567890abcdef...");
 * console.log(nsec); // "nsec1..."
 */
export declare function privateKeyToNsec(privateKey: string): string;
/**
 * Converts a private key to bech32 npub format
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The bech32-encoded npub public key
 * @throws {Error} If the private key is invalid
 * @example
 * const npub = privateKeyToNpub("1234567890abcdef...");
 * console.log(npub); // "npub1..."
 */
export declare function privateKeyToNpub(privateKey: string): string;
/**
 * Converts a bech32 nsec private key to hex format
 * @param {string} nsec - The bech32-encoded nsec private key
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the nsec key is invalid
 * @example
 * const hex = nsecToHex("nsec1...");
 * console.log(hex); // "1234567890abcdef..."
 */
export declare function nsecToHex(nsec: string): string;
/**
 * Converts a bech32 npub public key to hex format
 * @param {string} npub - The bech32-encoded npub public key
 * @returns {string} The hex-encoded public key
 * @throws {Error} If the npub key is invalid
 * @example
 * const hex = npubToHex("npub1...");
 * console.log(hex); // "1234567890abcdef..."
 */
export declare function npubToHex(npub: string): string;
/**
 * Converts a hex public key to bech32 npub format
 * @param {string} publicKeyHex - The hex-encoded public key
 * @returns {string} The bech32-encoded npub public key
 * @throws {Error} If the public key is invalid
 * @example
 * const npub = hexToNpub("1234567890abcdef...");
 * console.log(npub); // "npub1..."
 */
export declare function hexToNpub(publicKeyHex: string): string;
/**
 * Converts a hex private key to bech32 nsec format
 * @param {string} privateKeyHex - The hex-encoded private key
 * @returns {string} The bech32-encoded nsec private key
 * @throws {Error} If the private key is invalid
 * @example
 * const nsec = hexToNsec("1234567890abcdef...");
 * console.log(nsec); // "nsec1..."
 */
export declare function hexToNsec(privateKeyHex: string): string;
/**
 * Signs a message with a private key
 * @param {string} message - The message to sign
 * @param {string} privateKey - The hex-encoded private key to sign with
 * @returns {Promise<string>} The hex-encoded signature
 * @throws {Error} If signing fails
 * @example
 * const signature = await signMessage("Hello Nostr!", privateKey);
 * console.log(signature); // hex-encoded signature
 */
export declare function signMessage(message: string, privateKey: string): Promise<string>;
/**
 * Verifies a message signature
 * @param {string} message - The original message
 * @param {string} signature - The hex-encoded signature to verify
 * @param {string} publicKey - The hex-encoded public key to verify against
 * @returns {Promise<boolean>} True if the signature is valid, false otherwise
 * @example
 * const isValid = await verifySignature("Hello Nostr!", signature, publicKey);
 * console.log(isValid); // true or false
 */
export declare function verifySignature(message: string, signature: string, publicKey: string): Promise<boolean>;
/**
 * Converts a bech32 nsec private key to hex format
 * @param {string} nsec - The bech32-encoded nsec private key
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the nsec key is invalid
 * @example
 * const hex = nsecToPrivateKey("nsec1...");
 * console.log(hex); // "1234567890abcdef..."
 */
export declare function nsecToPrivateKey(nsec: string): string;
