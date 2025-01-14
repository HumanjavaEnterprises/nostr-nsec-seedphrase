"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.nip19 = void 0;
exports.generateSeedPhrase = generateSeedPhrase;
exports.getEntropyFromSeedPhrase = getEntropyFromSeedPhrase;
exports.validateSeedPhrase = validateSeedPhrase;
exports.seedPhraseToKeyPair = seedPhraseToKeyPair;
exports.generateKeyPairWithSeed = generateKeyPairWithSeed;
exports.fromHex = fromHex;
exports.getPublicKey = getPublicKey;
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
const bip39_1 = require("bip39");
const secp256k1 = __importStar(require("@noble/secp256k1"));
const utils_1 = require("@noble/hashes/utils");
const sha256_1 = require("@noble/hashes/sha256");
const hmac_1 = require("@noble/hashes/hmac");
const bech32_1 = require("bech32");
const logger_1 = require("./utils/logger");
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
    return (0, utils_1.hexToBytes)(entropyHex);
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
    logger_1.logger.log({ seedPhrase }, "Validating seed phrase");
    logger_1.logger.log({ seedPhrase }, "Input being validated");
    const isValid = (0, bip39_1.validateMnemonic)(seedPhrase);
    logger_1.logger.log({ isValid }, "Validated seed phrase");
    return Boolean(isValid);
}
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
function seedPhraseToKeyPair(seedPhrase) {
    try {
        const entropy = getEntropyFromSeedPhrase(seedPhrase);
        // Hash the entropy to generate a proper private key
        const privateKeyBytes = (0, sha256_1.sha256)(entropy);
        const privateKeyHex = (0, utils_1.bytesToHex)(privateKeyBytes);
        // Derive the public key
        const publicKeyBytes = secp256k1.getPublicKey(privateKeyHex, true); // Force compressed format
        const publicKey = (0, utils_1.bytesToHex)(publicKeyBytes);
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
        logger_1.logger.error("Failed to create key pair from seed phrase:", error?.toString());
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
        const privateKeyBytes = (0, utils_1.hexToBytes)(privateKeyHex);
        if (!secp256k1.utils.isValidPrivateKey(privateKeyBytes)) {
            throw new Error("Invalid private key");
        }
        // Derive the public key
        const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes, true); // Force compressed format
        const publicKey = (0, utils_1.bytesToHex)(publicKeyBytes);
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
        logger_1.logger.error("Failed to create key pair from hex:", error?.toString());
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
        const privateKeyBytes = (0, utils_1.hexToBytes)(privateKey);
        const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes, true); // Force compressed format
        return (0, utils_1.bytesToHex)(publicKeyBytes);
    }
    catch (error) {
        logger_1.logger.error("Failed to get public key:", error?.toString());
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
        const data = (0, utils_1.hexToBytes)(pubkey);
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
        return (0, utils_1.bytesToHex)(data instanceof Uint8Array ? data : Uint8Array.from(data));
    },
    /**
     * Encodes a private key into nsec format
     * @param {string} privkey - The hex-encoded private key
     * @returns {string} The bech32-encoded nsec string
     */
    nsecEncode(privkey) {
        const data = (0, utils_1.hexToBytes)(privkey);
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
        return (0, utils_1.bytesToHex)(data instanceof Uint8Array ? data : Uint8Array.from(data));
    },
    /**
     * Encodes an event ID into note format
     * @param {string} eventId - The hex-encoded event ID
     * @returns {string} The bech32-encoded note string
     */
    noteEncode(eventId) {
        const data = (0, utils_1.hexToBytes)(eventId);
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
        return (0, utils_1.bytesToHex)(data instanceof Uint8Array ? data : Uint8Array.from(data));
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
            data: data instanceof Uint8Array ? data : Uint8Array.from(data)
        };
    }
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
    return (0, utils_1.bytesToHex)((0, sha256_1.sha256)(new TextEncoder().encode(serialized)));
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
        const signature = await secp256k1.sign((0, utils_1.hexToBytes)(eventHash), (0, utils_1.hexToBytes)(privateKey));
        logger_1.logger.log("Event signed successfully");
        return (0, utils_1.bytesToHex)(signature.toCompactRawBytes());
    }
    catch (error) {
        logger_1.logger.error("Failed to sign event:", error?.toString());
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
            logger_1.logger.log("Invalid event: missing required fields");
            return false;
        }
        const hash = getEventHash(event);
        if (hash !== event.id) {
            logger_1.logger.log("Event hash mismatch");
            return false;
        }
        logger_1.logger.log("Verifying event signature");
        return await secp256k1.verify((0, utils_1.hexToBytes)(event.sig), (0, utils_1.hexToBytes)(hash), (0, utils_1.hexToBytes)(event.pubkey));
    }
    catch (error) {
        logger_1.logger.error("Failed to verify event:", error?.toString());
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
        const h = hmac_1.hmac.create(sha256_1.sha256, key);
        messages.forEach((msg) => h.update(msg));
        return h.digest();
    };
    const hmacSyncFunction = (key, ...messages) => {
        const h = hmac_1.hmac.create(sha256_1.sha256, key);
        messages.forEach((msg) => h.update(msg));
        return h.digest();
    };
    // Type assertion to handle the utils property
    secp256k1.utils = {
        ...secp256k1.utils,
        hmacSha256: hmacFunction,
        hmacSha256Sync: hmacSyncFunction,
    };
    logger_1.logger.log("Configured HMAC for secp256k1");
    logger_1.logger.log("secp256k1.utils after configuration:", secp256k1.utils);
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
    logger_1.logger.log("Created new Nostr event");
    return {
        ...event,
        id,
        sig,
    };
}
/**
 * Converts a BIP39 seed phrase to a private key
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
        logger_1.logger.error("Failed to encode nsec:", error?.toString());
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
        const privateKeyBytes = (0, utils_1.hexToBytes)(privateKey);
        const publicKey = secp256k1.getPublicKey(privateKeyBytes, true);
        return exports.nip19.npubEncode((0, utils_1.bytesToHex)(publicKey));
    }
    catch (error) {
        logger_1.logger.error("Failed to encode npub:", error?.toString());
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
        logger_1.logger.log("Converted nsec to hex");
        return hexPrivateKey;
    }
    catch (error) {
        logger_1.logger.error("Failed to decode nsec:", error?.toString());
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
        logger_1.logger.log("Converted npub to hex");
        return (0, utils_1.bytesToHex)(data);
    }
    catch (error) {
        logger_1.logger.error("Failed to decode npub:", error?.toString());
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
        logger_1.logger.log("Converting hex to npub");
        return exports.nip19.npubEncode(publicKeyHex);
    }
    catch (error) {
        logger_1.logger.error("Failed to encode npub:", error?.toString());
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
        logger_1.logger.log("Converting hex to nsec");
        return exports.nip19.nsecEncode(privateKeyHex);
    }
    catch (error) {
        logger_1.logger.error("Failed to encode nsec:", error?.toString());
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
        const messageHash = (0, sha256_1.sha256)(messageBytes);
        const signature = await secp256k1.sign(messageHash, (0, utils_1.hexToBytes)(privateKey));
        logger_1.logger.log("Message signed successfully");
        return (0, utils_1.bytesToHex)(signature.toCompactRawBytes());
    }
    catch (error) {
        logger_1.logger.error("Failed to sign message:", error?.toString());
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
        const messageHash = (0, sha256_1.sha256)(messageBytes);
        logger_1.logger.log("Verifying message signature");
        return await secp256k1.verify((0, utils_1.hexToBytes)(signature), messageHash, (0, utils_1.hexToBytes)(publicKey));
    }
    catch (error) {
        logger_1.logger.error("Failed to verify signature:", error?.toString());
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
        logger_1.logger.error("Failed to decode nsec:", error?.toString());
        throw error;
    }
}
