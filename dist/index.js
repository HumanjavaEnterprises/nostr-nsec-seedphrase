import { generateMnemonic as scureGenerateMnemonic, validateMnemonic as scureValidateMnemonic, mnemonicToEntropy as scureMnemonicToEntropy, mnemonicToSeedSync, } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { HDKey } from "@scure/bip32";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { bech32 } from "bech32";
import { encrypt as nip49Encrypt, decrypt as nip49Decrypt, } from "nostr-crypto-utils/nip49";
const generateMnemonic = () => scureGenerateMnemonic(english, 128);
const validateMnemonic = (m) => scureValidateMnemonic(m, english);
/**
 * Generates a new BIP39 seed phrase
 * @returns {string} A random 12-word BIP39 mnemonic seed phrase
 * @example
 * const seedPhrase = generateSeedPhrase();
 * console.log(seedPhrase); // "witch collapse practice feed shame open despair creek road again ice least"
 */
export function generateSeedPhrase() {
    return generateMnemonic();
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
export function getEntropyFromSeedPhrase(seedPhrase) {
    if (!validateMnemonic(seedPhrase)) {
        throw new Error("Invalid seed phrase");
    }
    return scureMnemonicToEntropy(seedPhrase, english);
}
/**
 * Validates a BIP39 seed phrase
 * @param {string} seedPhrase - The seed phrase to validate
 * @returns {boolean} True if the seed phrase is valid, false otherwise
 * @example
 * const isValid = validateSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(isValid); // true
 */
export function validateSeedPhrase(seedPhrase) {
    return validateMnemonic(seedPhrase);
}
/**
 * NIP-06 derivation path: BIP-44 purpose, SLIP-44 coin type 1237 (Nostr),
 * account 0. `m/44'/1237'/0'/0/0`.
 * @see https://github.com/nostr-protocol/nips/blob/master/06.md
 */
export const NIP06_DERIVATION_PATH = "m/44'/1237'/0'/0/0";
/**
 * Returns the NIP-06 derivation path for an account index:
 * `m/44'/1237'/<account>'/0/0`.
 * @param {number} [account=0] - Integer from 0 to 2^31 - 1
 * @returns {string} The BIP-32 derivation path
 * @throws {Error} If the account index is not a valid hardened index
 * @example
 * getNip06DerivationPath(1); // "m/44'/1237'/1'/0/0"
 */
export function getNip06DerivationPath(account = 0) {
    if (!Number.isInteger(account) || account < 0 || account > 0x7fffffff) {
        throw new Error("Invalid account index: must be an integer from 0 to 2147483647");
    }
    return `m/44'/1237'/${account}'/0/0`;
}
/**
 * Derives a Nostr private key from a BIP39 seed phrase per NIP-06:
 * BIP39 seed -> BIP32 master key -> derive `m/44'/1237'/<account>'/0/0`.
 *
 * This is the interoperable standard derivation used across the Nostr
 * ecosystem (Alby, nos2x, nak, ...): the same mnemonic produces the same
 * key everywhere.
 *
 * @param {string} seedPhrase - A valid BIP39 mnemonic
 * @param {SeedPhraseOptions} [options] - Account index and BIP-39 passphrase
 * @returns {string} The hex-encoded 32-byte private key
 * @throws {Error} If the seed phrase or account is invalid, or derivation fails
 */
function deriveNip06PrivateKey(seedPhrase, options) {
    if (options == null)
        options = {};
    if (typeof options !== "object" || Array.isArray(options)) {
        throw new TypeError("Invalid options: expected an object like { account, passphrase }");
    }
    const { account = 0, passphrase = "" } = options;
    const path = getNip06DerivationPath(account);
    if (typeof passphrase !== "string") {
        throw new Error("Invalid passphrase: must be a string");
    }
    if (!validateMnemonic(seedPhrase)) {
        throw new Error("Invalid seed phrase");
    }
    const seed = mnemonicToSeedSync(seedPhrase, passphrase); // 64-byte BIP39 seed
    const child = HDKey.fromMasterSeed(seed).derive(path);
    seed.fill(0); // zero sensitive material
    if (!child.privateKey || child.privateKey.length !== 32) {
        throw new Error("Failed to derive NIP-06 private key");
    }
    const privateKeyHex = bytesToHex(child.privateKey);
    child.wipePrivateData();
    return privateKeyHex;
}
/**
 * Converts a BIP39 seed phrase to a Nostr key pair using the standard
 * NIP-06 derivation (BIP32 path `m/44'/1237'/<account>'/0/0`).
 *
 * With no options the result is account 0 with no BIP-39 passphrase, exactly
 * as in earlier versions.
 *
 * NOTE (v0.8.0 BREAKING): prior versions derived the private key as
 * `sha256(bip39-entropy)`, which is NOT NIP-06 and does not interoperate
 * with other Nostr tooling. Identities created with earlier versions can be
 * recovered with {@link seedPhraseToKeyPairLegacy} /
 * {@link seedPhraseToPrivateKeyLegacy}.
 *
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @param {SeedPhraseOptions} [options] - `account` (default 0) and `passphrase` (default "")
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 * @example
 * const keyPair = seedPhraseToKeyPair("witch collapse practice feed shame open despair creek road again ice least");
 * const second = seedPhraseToKeyPair(phrase, { account: 1 });
 * const withPassphrase = seedPhraseToKeyPair(phrase, { passphrase: "extra words" });
 * console.log(keyPair.privateKey); // hex private key
 * console.log(keyPair.publicKey);  // hex public key
 * console.log(keyPair.nsec);       // bech32 nsec private key
 * console.log(keyPair.npub);       // bech32 npub public key
 */
export function seedPhraseToKeyPair(seedPhrase, options) {
    const privateKeyHex = deriveNip06PrivateKey(seedPhrase, options);
    // Derive the public key as a 32-byte x-only key (BIP-340 / Nostr)
    const publicKeyBytes = schnorr.getPublicKey(hexToBytes(privateKeyHex));
    const publicKey = bytesToHex(publicKeyBytes);
    // Generate the nsec and npub formats
    const nsec = nip19.nsecEncode(privateKeyHex);
    const npub = nip19.npubEncode(publicKey);
    return {
        privateKey: privateKeyHex,
        publicKey,
        nsec,
        npub,
        seedPhrase,
    };
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
export function seedPhraseToPrivateKeyLegacy(seedPhrase) {
    const entropy = getEntropyFromSeedPhrase(seedPhrase);
    const privateKeyBytes = sha256(entropy);
    entropy.fill(0); // zero sensitive material
    const privateKeyHex = bytesToHex(privateKeyBytes);
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
export function seedPhraseToKeyPairLegacy(seedPhrase) {
    const privateKeyHex = seedPhraseToPrivateKeyLegacy(seedPhrase);
    const publicKeyBytes = schnorr.getPublicKey(hexToBytes(privateKeyHex));
    const publicKey = bytesToHex(publicKeyBytes);
    return {
        privateKey: privateKeyHex,
        publicKey,
        nsec: nip19.nsecEncode(privateKeyHex),
        npub: nip19.npubEncode(publicKey),
        seedPhrase,
    };
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
export function generateKeyPairWithSeed() {
    const seedPhrase = generateMnemonic();
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
export function fromHex(privateKeyHex) {
    // Validate the private key
    const privateKeyBytes = hexToBytes(privateKeyHex);
    if (!secp256k1.utils.isValidSecretKey(privateKeyBytes)) {
        privateKeyBytes.fill(0); // zero sensitive material
        throw new Error("Invalid private key");
    }
    // Derive the public key as a 32-byte x-only key (BIP-340 / Nostr)
    const publicKeyBytes = schnorr.getPublicKey(privateKeyBytes);
    privateKeyBytes.fill(0); // zero sensitive material
    const publicKey = bytesToHex(publicKeyBytes);
    // Generate the nsec and npub formats
    const nsec = nip19.nsecEncode(privateKeyHex);
    const npub = nip19.npubEncode(publicKey);
    return {
        privateKey: privateKeyHex,
        publicKey,
        nsec,
        npub,
        seedPhrase: "", // No seed phrase for hex-imported keys
    };
}
/**
 * Derives a public key from a private key
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The hex-encoded public key
 * @example
 * const pubkey = getPublicKey("1234567890abcdef...");
 * console.log(pubkey); // hex public key
 */
export function getPublicKey(privateKey) {
    const privateKeyBytes = hexToBytes(privateKey);
    // 32-byte x-only public key (BIP-340 / Nostr identity)
    const publicKeyBytes = schnorr.getPublicKey(privateKeyBytes);
    privateKeyBytes.fill(0); // zero sensitive material
    return bytesToHex(publicKeyBytes);
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
export function getCompressedPublicKey(privateKey) {
    const privateKeyBytes = hexToBytes(privateKey);
    const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes, true);
    privateKeyBytes.fill(0); // zero sensitive material
    return bytesToHex(publicKeyBytes);
}
/**
 * Encodes exactly 32 bytes of hex under a bech32 prefix (NIP-19 bare keys and ids).
 */
function encode32(prefix, hex, what) {
    const data = hexToBytes(hex);
    if (data.length !== 32) {
        throw new Error(`Invalid ${what}: ${prefix} requires exactly 32 bytes, got ${data.length}`);
    }
    return bech32.encode(prefix, bech32.toWords(data), 1000);
}
/**
 * Decodes a bech32 string, checks its prefix, and requires a 32-byte payload.
 */
function decode32(prefix, str) {
    const { prefix: got, words } = bech32.decode(str, 1000);
    if (got !== prefix)
        throw new Error(`Invalid ${prefix}: wrong prefix`);
    const data = Uint8Array.from(bech32.fromWords(words));
    if (data.length !== 32) {
        throw new Error(`Invalid ${prefix}: expected a 32-byte payload, got ${data.length} bytes`);
    }
    return data;
}
/**
 * Throws unless the bytes are a valid secp256k1 secret key (0 < d < n).
 */
function assertValidSecretKey(data) {
    if (!secp256k1.utils.isValidSecretKey(data)) {
        throw new Error("Invalid private key: must be 32 bytes with 0 < d < n");
    }
}
/**
 * NIP-19 encoding and decoding functions for bare keys and event ids.
 * Every encoder and decoder requires exactly 32 bytes; nsec values must also
 * be a valid secp256k1 secret key (0 < d < n).
 * @namespace
 */
export const nip19 = {
    /**
     * Encodes a public key into npub format
     * @param {string} pubkey - The hex-encoded 32-byte x-only public key
     * @returns {string} The bech32-encoded npub string
     * @throws {Error} If the key is not exactly 32 bytes of hex
     */
    npubEncode(pubkey) {
        // Nostr npubs are 32-byte x-only public keys (BIP-340). Reject anything
        // else (e.g. a 33-byte compressed key) so it can never be silently encoded.
        return encode32("npub", pubkey, "public key");
    },
    /**
     * Decodes an npub string to hex format
     * @param {string} npub - The bech32-encoded npub string
     * @returns {string} The hex-encoded public key
     * @throws {Error} If the prefix is wrong or the payload is not 32 bytes
     */
    npubDecode(npub) {
        return bytesToHex(decode32("npub", npub));
    },
    /**
     * Encodes a private key into nsec format
     * @param {string} privkey - The hex-encoded 32-byte private key
     * @returns {string} The bech32-encoded nsec string
     * @throws {Error} If the key is not 32 bytes or not in the range 0 < d < n
     */
    nsecEncode(privkey) {
        const data = hexToBytes(privkey);
        try {
            assertValidSecretKey(data);
            return bech32.encode("nsec", bech32.toWords(data), 1000);
        }
        finally {
            data.fill(0); // zero sensitive material
        }
    },
    /**
     * Decodes an nsec string to hex format
     * @param {string} nsec - The bech32-encoded nsec string
     * @returns {string} The hex-encoded private key
     * @throws {Error} If the prefix is wrong, the payload is not 32 bytes, or
     *   the key is not in the range 0 < d < n
     */
    nsecDecode(nsec) {
        const data = decode32("nsec", nsec);
        try {
            assertValidSecretKey(data);
            return bytesToHex(data);
        }
        finally {
            data.fill(0); // zero sensitive material
        }
    },
    /**
     * Encodes an event ID into note format
     * @param {string} eventId - The hex-encoded 32-byte event ID
     * @returns {string} The bech32-encoded note string
     * @throws {Error} If the id is not exactly 32 bytes of hex
     */
    noteEncode(eventId) {
        return encode32("note", eventId, "event id");
    },
    /**
     * Decodes a note string to hex format
     * @param {string} note - The bech32-encoded note string
     * @returns {string} The hex-encoded event ID
     * @throws {Error} If the prefix is wrong or the payload is not 32 bytes
     */
    noteDecode(note) {
        return bytesToHex(decode32("note", note));
    },
    /**
     * Decodes any bech32-encoded Nostr entity without checking its prefix or
     * length. Prefer the typed decoders above, which validate both.
     * @param {string} bech32str - The bech32-encoded string
     * @returns {{ type: string; data: Uint8Array }} Object containing the decoded type and data
     * @property {string} type - The bech32 prefix (e.g. npub, nsec, note)
     * @property {Uint8Array} data - The raw decoded data
     */
    decode(bech32str) {
        const { prefix, words } = bech32.decode(bech32str, 1000);
        return { type: prefix, data: Uint8Array.from(bech32.fromWords(words)) };
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
    return bytesToHex(sha256(new TextEncoder().encode(serialized)));
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
export async function signEvent(event, privateKey) {
    const eventHash = getEventHash(event);
    const privateKeyBytes = hexToBytes(privateKey);
    const signature = schnorr.sign(hexToBytes(eventHash), privateKeyBytes);
    privateKeyBytes.fill(0); // zero sensitive material
    return bytesToHex(signature);
}
/**
 * Verifies a Nostr event signature
 * @param {NostrEvent} event - The event to verify
 * @returns {Promise<boolean>} True if the signature is valid, false otherwise
 * @example
 * const isValid = await verifyEvent(event);
 * console.log(isValid); // true or false
 */
export async function verifyEvent(event) {
    if (!event.id || !event.pubkey || !event.sig) {
        return false;
    }
    const hash = getEventHash(event);
    if (hash !== event.id) {
        return false;
    }
    return schnorr.verify(hexToBytes(event.sig), hexToBytes(hash), hexToBytes(event.pubkey));
}
/**
 * Configures secp256k1 with HMAC for WebSocket utilities
 * This is required for some WebSocket implementations
 * @example
 * configureHMAC();
 */
export function configureHMAC() {
    const hmacFunction = (key, ...messages) => {
        const h = hmac.create(sha256, key);
        messages.forEach((msg) => h.update(msg));
        return h.digest();
    };
    const hmacSyncFunction = (key, ...messages) => {
        const h = hmac.create(sha256, key);
        messages.forEach((msg) => h.update(msg));
        return h.digest();
    };
    // Safety check: only patch if utils exists and hmacSha256Sync is a known property
    if ("utils" in secp256k1 &&
        typeof secp256k1.utils?.hmacSha256Sync !== "undefined") {
        secp256k1.utils.hmacSha256 = hmacFunction;
        secp256k1.utils.hmacSha256Sync = hmacSyncFunction;
    }
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
export async function createEvent(content, kind, privateKey, tags = []) {
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
    return {
        ...event,
        id,
        sig,
    };
}
/**
 * Converts a BIP39 seed phrase to a private key using the standard NIP-06
 * derivation (BIP32 path `m/44'/1237'/<account>'/0/0`). Interoperable with Alby,
 * nos2x, nak, and other NIP-06 tooling. For identities created before
 * v0.8.0 see {@link seedPhraseToPrivateKeyLegacy}.
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @param {SeedPhraseOptions} [options] - `account` (default 0) and `passphrase` (default "")
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const privateKey = seedPhraseToPrivateKey("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(privateKey); // hex private key
 */
export function seedPhraseToPrivateKey(seedPhrase, options) {
    return seedPhraseToKeyPair(seedPhrase, options).privateKey;
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
export function privateKeyToNsec(privateKey) {
    return nip19.nsecEncode(privateKey);
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
export function privateKeyToNpub(privateKey) {
    const privateKeyBytes = hexToBytes(privateKey);
    // 32-byte x-only public key (BIP-340 / Nostr identity)
    const publicKey = schnorr.getPublicKey(privateKeyBytes);
    privateKeyBytes.fill(0); // zero sensitive material
    return nip19.npubEncode(bytesToHex(publicKey));
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
export function nsecToHex(nsec) {
    const hexPrivateKey = nip19.nsecDecode(nsec);
    return hexPrivateKey;
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
export function npubToHex(npub) {
    return nip19.npubDecode(npub);
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
export function hexToNpub(publicKeyHex) {
    return nip19.npubEncode(publicKeyHex);
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
export function hexToNsec(privateKeyHex) {
    return nip19.nsecEncode(privateKeyHex);
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
export async function signMessage(message, privateKey) {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    const messageHashHex = bytesToHex(messageHash);
    const privateKeyBytes = hexToBytes(privateKey);
    const signature = schnorr.sign(hexToBytes(messageHashHex), privateKeyBytes);
    privateKeyBytes.fill(0); // zero sensitive material
    return bytesToHex(signature);
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
export async function verifySignature(message, signature, publicKey) {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    const messageHashHex = bytesToHex(messageHash);
    return schnorr.verify(hexToBytes(signature), hexToBytes(messageHashHex), hexToBytes(publicKey));
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
export function nsecToPrivateKey(nsec) {
    return nip19.nsecDecode(nsec);
}
/**
 * Encrypts a hex private key into an ncryptsec bech32 string (NIP-49)
 * @param {string} privateKeyHex - The hex-encoded private key (64 hex chars / 32 bytes)
 * @param {string} password - The password to encrypt with
 * @param {number} [logn=16] - Scrypt log2(N) parameter (higher = slower but more secure)
 * @returns {string} The bech32-encoded ncryptsec string
 * @throws {Error} If the key is not 32 bytes with 0 < d < n, or encryption fails
 * @example
 * const ncryptsec = toNcryptsec("1234567890abcdef...", "my-strong-password");
 * console.log(ncryptsec); // "ncryptsec1..."
 */
export function toNcryptsec(privateKeyHex, password, logn = 16) {
    const secretBytes = hexToBytes(privateKeyHex);
    try {
        assertValidSecretKey(secretBytes);
        return nip49Encrypt(secretBytes, password, logn);
    }
    finally {
        secretBytes.fill(0); // zero sensitive material
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
export function fromNcryptsec(ncryptsec, password) {
    const secretBytes = nip49Decrypt(ncryptsec, password);
    const hex = bytesToHex(secretBytes);
    secretBytes.fill(0); // zero sensitive material
    return hex;
}
