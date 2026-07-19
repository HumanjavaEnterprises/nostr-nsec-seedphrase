"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nip19 = exports.NIP06_DERIVATION_PATH = void 0;
exports.generateSeedPhrase = generateSeedPhrase;
exports.getEntropyFromSeedPhrase = getEntropyFromSeedPhrase;
exports.validateSeedPhrase = validateSeedPhrase;
exports.seedPhraseToKeyPair = seedPhraseToKeyPair;
exports.seedPhraseToPrivateKeyLegacy = seedPhraseToPrivateKeyLegacy;
exports.seedPhraseToKeyPairLegacy = seedPhraseToKeyPairLegacy;
exports.generateKeyPairWithSeed = generateKeyPairWithSeed;
exports.fromHex = fromHex;
exports.getPublicKey = getPublicKey;
exports.getCompressedPublicKey = getCompressedPublicKey;
exports.signEvent = signEvent;
exports.verifyEvent = verifyEvent;
exports.configureHMAC = configureHMAC;
exports.createEvent = createEvent;
exports.seedPhraseToPrivateKey = seedPhraseToPrivateKey;
exports.privateKeyToNsec = privateKeyToNsec;
exports.privateKeyToNpub = privateKeyToNpub;
exports.nsecToHex = nsecToHex;
exports.npubToHex = npubToHex;
exports.hexToNpub = hexToNpub;
exports.hexToNsec = hexToNsec;
exports.signMessage = signMessage;
exports.verifySignature = verifySignature;
exports.nsecToPrivateKey = nsecToPrivateKey;
exports.toNcryptsec = toNcryptsec;
exports.fromNcryptsec = fromNcryptsec;
const bip39_1 = require("bip39");
const bip32_1 = require("@scure/bip32");
const secp256k1_js_1 = require("@noble/curves/secp256k1.js");
const utils_js_1 = require("@noble/hashes/utils.js");
const sha2_js_1 = require("@noble/hashes/sha2.js");
const hmac_js_1 = require("@noble/hashes/hmac.js");
const bech32_1 = require("bech32");
const nostr_crypto_utils_1 = require("nostr-crypto-utils");
const logger_js_1 = require("./utils/logger.js");
/**
 * Generates a new BIP39 seed phrase
 * @returns {string} A random 12-word BIP39 mnemonic seed phrase
 * @example
 * const seedPhrase = generateSeedPhrase();
 * console.log(seedPhrase); // "witch collapse practice feed shame open despair creek road again ice least"
 */
function generateSeedPhrase() {
    return (0, bip39_1.generateMnemonic)();
}
/**
 * Converts a BIP39 seed phrase to its entropy value
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {Uint8Array} The entropy value
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const entropy = getEntropyFromSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(entropy); // Uint8Array
 */
function getEntropyFromSeedPhrase(seedPhrase) {
    if (!(0, bip39_1.validateMnemonic)(seedPhrase)) {
        throw new Error("Invalid seed phrase");
    }
    // bip39.mnemonicToEntropy returns a hex string, convert it to Uint8Array
    const entropyHex = (0, bip39_1.mnemonicToEntropy)(seedPhrase);
    return (0, utils_js_1.hexToBytes)(entropyHex);
}
/**
 * Validates a BIP39 seed phrase
 * @param {string} seedPhrase - The seed phrase to validate
 * @returns {boolean} True if the seed phrase is valid, false otherwise
 * @example
 * const isValid = validateSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(isValid); // true
 */
function validateSeedPhrase(seedPhrase) {
    logger_js_1.logger.log("Validating seed phrase");
    logger_js_1.logger.log("Input being validated");
    const isValid = (0, bip39_1.validateMnemonic)(seedPhrase);
    logger_js_1.logger.log({ isValid }, "Validated seed phrase");
    return Boolean(isValid);
}
/**
 * NIP-06 derivation path: BIP-44 purpose, SLIP-44 coin type 1237 (Nostr),
 * account 0. `m/44'/1237'/0'/0/0`.
 * @see https://github.com/nostr-protocol/nips/blob/master/06.md
 */
exports.NIP06_DERIVATION_PATH = "m/44'/1237'/0'/0/0";
/**
 * Derives a Nostr private key from a BIP39 seed phrase per NIP-06:
 * BIP39 seed -> BIP32 master key -> derive `m/44'/1237'/0'/0/0`.
 *
 * This is the interoperable standard derivation used across the Nostr
 * ecosystem (Alby, nos2x, nak, ...): the same mnemonic produces the same
 * key everywhere.
 *
 * @param {string} seedPhrase - A valid BIP39 mnemonic
 * @returns {string} The hex-encoded 32-byte private key
 * @throws {Error} If the seed phrase is invalid or derivation fails
 */
function deriveNip06PrivateKey(seedPhrase) {
    if (!(0, bip39_1.validateMnemonic)(seedPhrase)) {
        throw new Error("Invalid seed phrase");
    }
    const seed = (0, bip39_1.mnemonicToSeedSync)(seedPhrase); // 64-byte BIP39 seed
    const child = bip32_1.HDKey.fromMasterSeed(seed).derive(exports.NIP06_DERIVATION_PATH);
    seed.fill(0); // zero sensitive material
    if (!child.privateKey || child.privateKey.length !== 32) {
        throw new Error("Failed to derive NIP-06 private key");
    }
    const privateKeyHex = (0, utils_js_1.bytesToHex)(child.privateKey);
    child.wipePrivateData();
    return privateKeyHex;
}
/**
 * Converts a BIP39 seed phrase to a Nostr key pair using the standard
 * NIP-06 derivation (BIP32 path `m/44'/1237'/0'/0/0`).
 *
 * NOTE (v0.8.0 BREAKING): prior versions derived the private key as
 * `sha256(bip39-entropy)`, which is NOT NIP-06 and does not interoperate
 * with other Nostr tooling. Identities created with earlier versions can be
 * recovered with {@link seedPhraseToKeyPairLegacy} /
 * {@link seedPhraseToPrivateKeyLegacy}.
 *
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
function seedPhraseToKeyPair(seedPhrase) {
    try {
        const privateKeyHex = deriveNip06PrivateKey(seedPhrase);
        // Derive the public key as a 32-byte x-only key (BIP-340 / Nostr)
        const publicKeyBytes = secp256k1_js_1.schnorr.getPublicKey((0, utils_js_1.hexToBytes)(privateKeyHex));
        const publicKey = (0, utils_js_1.bytesToHex)(publicKeyBytes);
        // Generate the nsec and npub formats
        const nsec = exports.nip19.nsecEncode(privateKeyHex);
        const npub = exports.nip19.npubEncode(publicKey);
        return {
            privateKey: privateKeyHex,
            publicKey,
            nsec,
            npub,
            seedPhrase,
        };
    }
    catch (error) {
        logger_js_1.logger.error("Failed to create key pair from seed phrase:", error?.toString());
        throw error;
    }
}
/**
 * LEGACY (pre-0.8.0) derivation: converts a BIP39 seed phrase to a private
 * key as `sha256(bip39-entropy)`.
 *
 * This is NOT NIP-06 and is NOT interoperable with other Nostr tooling. It
 * exists solely to recover identities created with nostr-nsec-seedphrase
 * before the NIP-06 fix in v0.8.0. For all new identities use
 * {@link seedPhraseToPrivateKey}.
 *
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {string} The hex-encoded private key (legacy sha256-of-entropy)
 * @throws {Error} If the seed phrase is invalid
 */
function seedPhraseToPrivateKeyLegacy(seedPhrase) {
    const entropy = getEntropyFromSeedPhrase(seedPhrase);
    const privateKeyBytes = (0, sha2_js_1.sha256)(entropy);
    entropy.fill(0); // zero sensitive material
    const privateKeyHex = (0, utils_js_1.bytesToHex)(privateKeyBytes);
    privateKeyBytes.fill(0); // zero sensitive material
    return privateKeyHex;
}
/**
 * LEGACY (pre-0.8.0) variant of {@link seedPhraseToKeyPair}: full key pair
 * from the old `sha256(bip39-entropy)` derivation, including nsec/npub.
 *
 * Use only to recover identities created before the NIP-06 fix in v0.8.0.
 *
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {KeyPair} The legacy key pair
 * @throws {Error} If the seed phrase is invalid
 */
function seedPhraseToKeyPairLegacy(seedPhrase) {
    try {
        const privateKeyHex = seedPhraseToPrivateKeyLegacy(seedPhrase);
        const publicKeyBytes = secp256k1_js_1.schnorr.getPublicKey((0, utils_js_1.hexToBytes)(privateKeyHex));
        const publicKey = (0, utils_js_1.bytesToHex)(publicKeyBytes);
        return {
            privateKey: privateKeyHex,
            publicKey,
            nsec: exports.nip19.nsecEncode(privateKeyHex),
            npub: exports.nip19.npubEncode(publicKey),
            seedPhrase,
        };
    }
    catch (error) {
        logger_js_1.logger.error("Failed to create legacy key pair from seed phrase:", error?.toString());
        throw error;
    }
}
/**
 * Generates a new key pair with a random seed phrase
 * @returns {KeyPair} A new key pair containing private and public keys in various formats
 * @example
 * const keyPair = generateKeyPairWithSeed();
 * console.log(keyPair.seedPhrase); // random seed phrase
 * console.log(keyPair.privateKey);  // hex private key
 * console.log(keyPair.publicKey);   // hex public key
 */
function generateKeyPairWithSeed() {
    const seedPhrase = (0, bip39_1.generateMnemonic)();
    return seedPhraseToKeyPair(seedPhrase);
}
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
function fromHex(privateKeyHex) {
    try {
        // Validate the private key
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKeyHex);
        if (!secp256k1_js_1.secp256k1.utils.isValidSecretKey(privateKeyBytes)) {
            privateKeyBytes.fill(0); // zero sensitive material
            throw new Error("Invalid private key");
        }
        // Derive the public key as a 32-byte x-only key (BIP-340 / Nostr)
        const publicKeyBytes = secp256k1_js_1.schnorr.getPublicKey(privateKeyBytes);
        privateKeyBytes.fill(0); // zero sensitive material
        const publicKey = (0, utils_js_1.bytesToHex)(publicKeyBytes);
        // Generate the nsec and npub formats
        const nsec = exports.nip19.nsecEncode(privateKeyHex);
        const npub = exports.nip19.npubEncode(publicKey);
        return {
            privateKey: privateKeyHex,
            publicKey,
            nsec,
            npub,
            seedPhrase: "", // No seed phrase for hex-imported keys
        };
    }
    catch (error) {
        logger_js_1.logger.error("Failed to create key pair from hex:", error?.toString());
        throw error;
    }
}
/**
 * Derives a public key from a private key
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The hex-encoded public key
 * @example
 * const pubkey = getPublicKey("1234567890abcdef...");
 * console.log(pubkey); // hex public key
 */
function getPublicKey(privateKey) {
    try {
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKey);
        // 32-byte x-only public key (BIP-340 / Nostr identity)
        const publicKeyBytes = secp256k1_js_1.schnorr.getPublicKey(privateKeyBytes);
        privateKeyBytes.fill(0); // zero sensitive material
        return (0, utils_js_1.bytesToHex)(publicKeyBytes);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to get public key:", error?.toString());
        throw error;
    }
}
/**
 * Derives the 33-byte SEC1 compressed public key from a private key.
 *
 * This is NOT a valid Nostr/BIP-340 identity key. Nostr uses 32-byte x-only
 * public keys (see {@link getPublicKey}). Only use this if you specifically
 * need the compressed SEC1 encoding for ECDH or interop with non-Nostr tooling.
 *
 * @deprecated For Nostr identity use {@link getPublicKey} (x-only). Do not
 *   encode the output of this function as an npub.
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The 66-hex-char (33-byte) compressed public key
 */
function getCompressedPublicKey(privateKey) {
    try {
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKey);
        const publicKeyBytes = secp256k1_js_1.secp256k1.getPublicKey(privateKeyBytes, true);
        privateKeyBytes.fill(0); // zero sensitive material
        return (0, utils_js_1.bytesToHex)(publicKeyBytes);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to get compressed public key:", error?.toString());
        throw error;
    }
}
/**
 * NIP-19 encoding and decoding functions
 * @namespace
 */
exports.nip19 = {
    /**
     * Encodes a public key into npub format
     * @param {string} pubkey - The hex-encoded public key
     * @returns {string} The bech32-encoded npub string
     */
    npubEncode(pubkey) {
        const data = (0, utils_js_1.hexToBytes)(pubkey);
        // Nostr npubs are 32-byte x-only public keys (BIP-340). Reject anything
        // else (e.g. a 33-byte compressed key) so it can never be silently encoded.
        if (data.length !== 32) {
            throw new Error(`Invalid public key: npub requires a 32-byte x-only key, got ${data.length} bytes`);
        }
        const words = bech32_1.bech32.toWords(Uint8Array.from(data));
        return bech32_1.bech32.encode("npub", words, 1000);
    },
    /**
     * Decodes an npub string to hex format
     * @param {string} npub - The bech32-encoded npub string
     * @returns {string} The hex-encoded public key
     */
    npubDecode(npub) {
        const { prefix, words } = bech32_1.bech32.decode(npub, 1000);
        if (prefix !== "npub")
            throw new Error("Invalid npub: wrong prefix");
        const data = bech32_1.bech32.fromWords(words);
        return (0, utils_js_1.bytesToHex)(data instanceof Uint8Array ? data : Uint8Array.from(data));
    },
    /**
     * Encodes a private key into nsec format
     * @param {string} privkey - The hex-encoded private key
     * @returns {string} The bech32-encoded nsec string
     */
    nsecEncode(privkey) {
        const data = (0, utils_js_1.hexToBytes)(privkey);
        const words = bech32_1.bech32.toWords(Uint8Array.from(data));
        return bech32_1.bech32.encode("nsec", words, 1000);
    },
    /**
     * Decodes an nsec string to hex format
     * @param {string} nsec - The bech32-encoded nsec string
     * @returns {string} The hex-encoded private key
     */
    nsecDecode(nsec) {
        const { prefix, words } = bech32_1.bech32.decode(nsec, 1000);
        if (prefix !== "nsec")
            throw new Error("Invalid nsec: wrong prefix");
        const data = bech32_1.bech32.fromWords(words);
        return (0, utils_js_1.bytesToHex)(data instanceof Uint8Array ? data : Uint8Array.from(data));
    },
    /**
     * Encodes an event ID into note format
     * @param {string} eventId - The hex-encoded event ID
     * @returns {string} The bech32-encoded note string
     */
    noteEncode(eventId) {
        const data = (0, utils_js_1.hexToBytes)(eventId);
        const words = bech32_1.bech32.toWords(Uint8Array.from(data));
        return bech32_1.bech32.encode("note", words, 1000);
    },
    /**
     * Decodes a note string to hex format
     * @param {string} note - The bech32-encoded note string
     * @returns {string} The hex-encoded event ID
     */
    noteDecode(note) {
        const { prefix, words } = bech32_1.bech32.decode(note, 1000);
        if (prefix !== "note")
            throw new Error("Invalid note: wrong prefix");
        const data = bech32_1.bech32.fromWords(words);
        return (0, utils_js_1.bytesToHex)(data instanceof Uint8Array ? data : Uint8Array.from(data));
    },
    /**
     * Decodes any bech32-encoded Nostr entity
     * @param {string} bech32str - The bech32-encoded string
     * @returns {{ type: string; data: Uint8Array }} Object containing the decoded type and data
     * @property {string} type - The type of the decoded entity (npub, nsec, or note)
     * @property {Uint8Array} data - The raw decoded data
     */
    decode(bech32str) {
        const { prefix, words } = bech32_1.bech32.decode(bech32str, 1000);
        const data = bech32_1.bech32.fromWords(words);
        return {
            type: prefix,
            data: data instanceof Uint8Array ? data : Uint8Array.from(data),
        };
    },
};
/**
 * Calculates the event hash/ID according to the Nostr protocol
 * @param {UnsignedEvent} event - The event to hash
 * @returns {string} The hex-encoded event hash
 */
function getEventHash(event) {
    const serialized = JSON.stringify([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
    ]);
    return (0, utils_js_1.bytesToHex)((0, sha2_js_1.sha256)(new TextEncoder().encode(serialized)));
}
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
async function signEvent(event, privateKey) {
    try {
        const eventHash = getEventHash(event);
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKey);
        const signature = secp256k1_js_1.schnorr.sign((0, utils_js_1.hexToBytes)(eventHash), privateKeyBytes);
        privateKeyBytes.fill(0); // zero sensitive material
        logger_js_1.logger.log("Event signed successfully");
        return (0, utils_js_1.bytesToHex)(signature);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to sign event:", error?.toString());
        throw error;
    }
}
/**
 * Verifies a Nostr event signature
 * @param {NostrEvent} event - The event to verify
 * @returns {Promise<boolean>} True if the signature is valid, false otherwise
 * @example
 * const isValid = await verifyEvent(event);
 * console.log(isValid); // true or false
 */
async function verifyEvent(event) {
    try {
        if (!event.id || !event.pubkey || !event.sig) {
            logger_js_1.logger.log("Invalid event: missing required fields");
            return false;
        }
        const hash = getEventHash(event);
        if (hash !== event.id) {
            logger_js_1.logger.log("Event hash mismatch");
            return false;
        }
        logger_js_1.logger.log("Verifying event signature");
        return secp256k1_js_1.schnorr.verify((0, utils_js_1.hexToBytes)(event.sig), (0, utils_js_1.hexToBytes)(hash), (0, utils_js_1.hexToBytes)(event.pubkey));
    }
    catch (error) {
        logger_js_1.logger.error("Failed to verify event:", error?.toString());
        throw error;
    }
}
/**
 * Configures secp256k1 with HMAC for WebSocket utilities
 * This is required for some WebSocket implementations
 * @example
 * configureHMAC();
 */
function configureHMAC() {
    const hmacFunction = (key, ...messages) => {
        const h = hmac_js_1.hmac.create(sha2_js_1.sha256, key);
        messages.forEach((msg) => h.update(msg));
        return h.digest();
    };
    const hmacSyncFunction = (key, ...messages) => {
        const h = hmac_js_1.hmac.create(sha2_js_1.sha256, key);
        messages.forEach((msg) => h.update(msg));
        return h.digest();
    };
    // Safety check: only patch if utils exists and hmacSha256Sync is a known property
    if ("utils" in secp256k1_js_1.secp256k1 &&
        typeof secp256k1_js_1.secp256k1.utils?.hmacSha256Sync !== "undefined") {
        secp256k1_js_1.secp256k1.utils.hmacSha256 = hmacFunction;
        secp256k1_js_1.secp256k1.utils.hmacSha256Sync = hmacSyncFunction;
    }
    else {
        logger_js_1.logger.log("secp256k1.utils.hmacSha256Sync not found; HMAC configuration skipped (library may handle HMAC internally)");
    }
    logger_js_1.logger.log("Configured HMAC for secp256k1");
}
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
async function createEvent(content, kind, privateKey, tags = []) {
    const publicKey = getPublicKey(privateKey);
    const event = {
        pubkey: publicKey,
        created_at: Math.floor(Date.now() / 1000),
        kind,
        tags,
        content,
    };
    const id = getEventHash(event);
    const sig = await signEvent(event, privateKey);
    logger_js_1.logger.log("Created new Nostr event");
    return {
        ...event,
        id,
        sig,
    };
}
/**
 * Converts a BIP39 seed phrase to a private key using the standard NIP-06
 * derivation (BIP32 path `m/44'/1237'/0'/0/0`). Interoperable with Alby,
 * nos2x, nak, and other NIP-06 tooling. For identities created before
 * v0.8.0 see {@link seedPhraseToPrivateKeyLegacy}.
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const privateKey = seedPhraseToPrivateKey("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(privateKey); // hex private key
 */
function seedPhraseToPrivateKey(seedPhrase) {
    return seedPhraseToKeyPair(seedPhrase).privateKey;
}
/**
 * Converts a private key to bech32 nsec format
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The bech32-encoded nsec private key
 * @throws {Error} If the private key is invalid
 * @example
 * const nsec = privateKeyToNsec("1234567890abcdef...");
 * console.log(nsec); // "nsec1..."
 */
function privateKeyToNsec(privateKey) {
    try {
        return exports.nip19.nsecEncode(privateKey);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to encode nsec:", error?.toString());
        throw error;
    }
}
/**
 * Converts a private key to bech32 npub format
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The bech32-encoded npub public key
 * @throws {Error} If the private key is invalid
 * @example
 * const npub = privateKeyToNpub("1234567890abcdef...");
 * console.log(npub); // "npub1..."
 */
function privateKeyToNpub(privateKey) {
    try {
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKey);
        // 32-byte x-only public key (BIP-340 / Nostr identity)
        const publicKey = secp256k1_js_1.schnorr.getPublicKey(privateKeyBytes);
        privateKeyBytes.fill(0); // zero sensitive material
        return exports.nip19.npubEncode((0, utils_js_1.bytesToHex)(publicKey));
    }
    catch (error) {
        logger_js_1.logger.error("Failed to encode npub:", error?.toString());
        throw error;
    }
}
/**
 * Converts a bech32 nsec private key to hex format
 * @param {string} nsec - The bech32-encoded nsec private key
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the nsec key is invalid
 * @example
 * const hex = nsecToHex("nsec1...");
 * console.log(hex); // "1234567890abcdef..."
 */
function nsecToHex(nsec) {
    try {
        const hexPrivateKey = exports.nip19.nsecDecode(nsec);
        logger_js_1.logger.log("Converted nsec to hex");
        return hexPrivateKey;
    }
    catch (error) {
        logger_js_1.logger.error("Failed to decode nsec:", error?.toString());
        throw error;
    }
}
/**
 * Converts a bech32 npub public key to hex format
 * @param {string} npub - The bech32-encoded npub public key
 * @returns {string} The hex-encoded public key
 * @throws {Error} If the npub key is invalid
 * @example
 * const hex = npubToHex("npub1...");
 * console.log(hex); // "1234567890abcdef..."
 */
function npubToHex(npub) {
    try {
        const { type, data } = exports.nip19.decode(npub);
        if (type !== "npub") {
            throw new Error("Invalid npub format");
        }
        logger_js_1.logger.log("Converted npub to hex");
        return (0, utils_js_1.bytesToHex)(data);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to decode npub:", error?.toString());
        throw error;
    }
}
/**
 * Converts a hex public key to bech32 npub format
 * @param {string} publicKeyHex - The hex-encoded public key
 * @returns {string} The bech32-encoded npub public key
 * @throws {Error} If the public key is invalid
 * @example
 * const npub = hexToNpub("1234567890abcdef...");
 * console.log(npub); // "npub1..."
 */
function hexToNpub(publicKeyHex) {
    try {
        logger_js_1.logger.log("Converting hex to npub");
        return exports.nip19.npubEncode(publicKeyHex);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to encode npub:", error?.toString());
        throw error;
    }
}
/**
 * Converts a hex private key to bech32 nsec format
 * @param {string} privateKeyHex - The hex-encoded private key
 * @returns {string} The bech32-encoded nsec private key
 * @throws {Error} If the private key is invalid
 * @example
 * const nsec = hexToNsec("1234567890abcdef...");
 * console.log(nsec); // "nsec1..."
 */
function hexToNsec(privateKeyHex) {
    try {
        logger_js_1.logger.log("Converting hex to nsec");
        return exports.nip19.nsecEncode(privateKeyHex);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to encode nsec:", error?.toString());
        throw error;
    }
}
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
async function signMessage(message, privateKey) {
    try {
        const messageBytes = new TextEncoder().encode(message);
        const messageHash = (0, sha2_js_1.sha256)(messageBytes);
        const messageHashHex = (0, utils_js_1.bytesToHex)(messageHash);
        const privateKeyBytes = (0, utils_js_1.hexToBytes)(privateKey);
        const signature = secp256k1_js_1.schnorr.sign((0, utils_js_1.hexToBytes)(messageHashHex), privateKeyBytes);
        privateKeyBytes.fill(0); // zero sensitive material
        logger_js_1.logger.log("Message signed successfully");
        return (0, utils_js_1.bytesToHex)(signature);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to sign message:", error?.toString());
        throw error;
    }
}
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
async function verifySignature(message, signature, publicKey) {
    try {
        const messageBytes = new TextEncoder().encode(message);
        const messageHash = (0, sha2_js_1.sha256)(messageBytes);
        const messageHashHex = (0, utils_js_1.bytesToHex)(messageHash);
        logger_js_1.logger.log("Verifying message signature");
        return secp256k1_js_1.schnorr.verify((0, utils_js_1.hexToBytes)(signature), (0, utils_js_1.hexToBytes)(messageHashHex), (0, utils_js_1.hexToBytes)(publicKey));
    }
    catch (error) {
        logger_js_1.logger.error("Failed to verify signature:", error?.toString());
        throw error;
    }
}
/**
 * Converts a bech32 nsec private key to hex format
 * @param {string} nsec - The bech32-encoded nsec private key
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the nsec key is invalid
 * @example
 * const hex = nsecToPrivateKey("nsec1...");
 * console.log(hex); // "1234567890abcdef..."
 */
function nsecToPrivateKey(nsec) {
    try {
        return exports.nip19.nsecDecode(nsec);
    }
    catch (error) {
        logger_js_1.logger.error("Failed to decode nsec:", error?.toString());
        throw error;
    }
}
/**
 * Encrypts a hex private key into an ncryptsec bech32 string (NIP-49)
 * @param {string} privateKeyHex - The hex-encoded private key (64 hex chars / 32 bytes)
 * @param {string} password - The password to encrypt with
 * @param {number} [logn=16] - Scrypt log2(N) parameter (higher = slower but more secure)
 * @returns {string} The bech32-encoded ncryptsec string
 * @throws {Error} If encryption fails
 * @example
 * const ncryptsec = toNcryptsec("1234567890abcdef...", "my-strong-password");
 * console.log(ncryptsec); // "ncryptsec1..."
 */
function toNcryptsec(privateKeyHex, password, logn = 16) {
    try {
        const secretBytes = (0, utils_js_1.hexToBytes)(privateKeyHex);
        const result = nostr_crypto_utils_1.nip49.encrypt(secretBytes, password, logn);
        secretBytes.fill(0); // zero sensitive material
        return result;
    }
    catch (error) {
        logger_js_1.logger.error("Failed to encrypt private key to ncryptsec:", error?.toString());
        throw error;
    }
}
/**
 * Decrypts an ncryptsec bech32 string back to a hex private key (NIP-49)
 * @param {string} ncryptsec - The bech32-encoded ncryptsec string
 * @param {string} password - The password used for encryption
 * @returns {string} The hex-encoded private key
 * @throws {Error} If decryption fails (wrong password, invalid format, etc.)
 * @example
 * const privateKeyHex = fromNcryptsec("ncryptsec1...", "my-strong-password");
 * console.log(privateKeyHex); // "1234567890abcdef..."
 */
function fromNcryptsec(ncryptsec, password) {
    try {
        const secretBytes = nostr_crypto_utils_1.nip49.decrypt(ncryptsec, password);
        const hex = (0, utils_js_1.bytesToHex)(secretBytes);
        secretBytes.fill(0); // zero sensitive material
        return hex;
    }
    catch (error) {
        logger_js_1.logger.error("Failed to decrypt ncryptsec:", error?.toString());
        throw error;
    }
}
