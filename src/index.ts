import { generateMnemonic, validateMnemonic, mnemonicToEntropy } from "bip39";
import * as secp256k1 from "@noble/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import * as nip19 from "nostr-tools/nip19";
import { getPublicKey, getEventHash } from "nostr-tools/pure";
import { pino } from "pino";

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  transport: {
    target: "pino-pretty",
    options: {
      colorize: true,
    },
  },
});

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
export function generateSeedPhrase(): string {
  return generateMnemonic();
}

/**
 * Converts a BIP39 seed phrase to its entropy value
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {string} The hex-encoded entropy value
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const entropy = getEntropyFromSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(entropy); // "0123456789abcdef0123456789abcdef"
 */
export function getEntropyFromSeedPhrase(seedPhrase: string): string {
  if (!validateMnemonic(seedPhrase)) {
    throw new Error("Invalid seed phrase");
  }
  const entropy = mnemonicToEntropy(seedPhrase);
  return entropy;
}

/**
 * Validates a BIP39 seed phrase
 * @param {string} seedPhrase - The seed phrase to validate
 * @returns {boolean} True if the seed phrase is valid, false otherwise
 * @example
 * const isValid = validateSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(isValid); // true
 */
export function validateSeedPhrase(seedPhrase: string): boolean {
  try {
    const isValid = validateMnemonic(seedPhrase);
    logger.debug({ isValid }, "Validated seed phrase");
    return isValid;
  } catch (error) {
    logger.error("Failed to validate seed phrase:", error);
    return false;
  }
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
export function seedPhraseToKeyPair(seedPhrase: string): KeyPair {
  try {
    const entropy = getEntropyFromSeedPhrase(seedPhrase);
    // Hash the entropy to generate a proper private key
    const privateKeyBytes = sha256(hexToBytes(entropy));
    const privateKeyHex = bytesToHex(privateKeyBytes);
    const publicKey = getPublicKey(privateKeyBytes);
    const nsec = nip19.nsecEncode(privateKeyBytes);
    const npub = nip19.npubEncode(publicKey);

    logger.debug("Created key pair from seed phrase");
    return {
      privateKey: privateKeyHex,
      publicKey,
      nsec,
      npub,
      seedPhrase,
    };
  } catch (error) {
    logger.error("Failed to create key pair from seed phrase:", error);
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
export function generateKeyPairWithSeed(): KeyPair {
  try {
    const seedPhrase = generateSeedPhrase();
    logger.debug("Generated new seed phrase");
    return seedPhraseToKeyPair(seedPhrase);
  } catch (error) {
    logger.error("Failed to generate key pair with seed phrase:", error);
    throw error;
  }
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
export function fromHex(privateKeyHex: string): KeyPair {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error(
        "Invalid hex private key format. Must be 64 characters of hex.",
      );
    }

    const privateKeyBytes = hexToBytes(privateKeyHex);
    const publicKey = getPublicKey(privateKeyBytes);
    const nsec = nip19.nsecEncode(privateKeyBytes);
    const npub = nip19.npubEncode(publicKey);

    logger.debug("Created key pair from hex private key");
    return {
      privateKey: privateKeyHex,
      publicKey,
      nsec,
      npub,
      seedPhrase: "",
    };
  } catch (error) {
    logger.error("Failed to create key pair from hex:", error);
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
export function nsecToHex(nsec: string): string {
  try {
    const { type, data } = nip19.decode(nsec);
    if (type !== "nsec") {
      throw new Error("Invalid nsec format");
    }
    logger.debug("Converted nsec to hex");
    return bytesToHex(data as Uint8Array);
  } catch (error) {
    logger.error("Failed to convert nsec to hex:", error);
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
export function npubToHex(npub: string): string {
  try {
    const { type, data } = nip19.decode(npub);
    if (type !== "npub") {
      throw new Error("Invalid npub format");
    }
    logger.debug("Converted npub to hex");
    return data as string;
  } catch (error) {
    logger.error("Failed to convert npub to hex:", error);
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
export function hexToNpub(publicKeyHex: string): string {
  try {
    logger.debug("Converting hex to npub");
    return nip19.npubEncode(publicKeyHex);
  } catch (error) {
    logger.error("Failed to convert hex to npub:", error);
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
export function hexToNsec(privateKeyHex: string): string {
  try {
    logger.debug("Converting hex to nsec");
    return nip19.nsecEncode(hexToBytes(privateKeyHex));
  } catch (error) {
    logger.error("Failed to convert hex to nsec:", error);
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
export async function signMessage(
  message: string,
  privateKey: string,
): Promise<string> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    const signature = await secp256k1.sign(messageHash, hexToBytes(privateKey));
    logger.debug("Message signed successfully");
    return bytesToHex(signature.toCompactRawBytes());
  } catch (error) {
    logger.error("Failed to sign message:", error);
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
export async function verifySignature(
  message: string,
  signature: string,
  publicKey: string,
): Promise<boolean> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    logger.debug("Verifying message signature");
    return await secp256k1.verify(
      hexToBytes(signature),
      messageHash,
      hexToBytes(publicKey),
    );
  } catch (error) {
    logger.error("Failed to verify signature:", error);
    throw error;
  }
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
export async function signEvent(
  event: UnsignedEvent,
  privateKey: string,
): Promise<string> {
  try {
    const eventHash = getEventHash(event);
    const signature = await secp256k1.sign(
      hexToBytes(eventHash),
      hexToBytes(privateKey),
    );
    logger.debug("Event signed successfully");
    return bytesToHex(signature.toCompactRawBytes());
  } catch (error) {
    logger.error("Failed to sign event:", error);
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
export async function verifyEvent(event: NostrEvent): Promise<boolean> {
  try {
    if (!event.id || !event.pubkey || !event.sig) {
      logger.warn("Invalid event: missing required fields");
      return false;
    }

    const hash = getEventHash(event);
    if (hash !== event.id) {
      logger.warn("Event hash mismatch");
      return false;
    }

    logger.debug("Verifying event signature");
    return await secp256k1.verify(
      hexToBytes(event.sig),
      hexToBytes(hash),
      hexToBytes(event.pubkey),
    );
  } catch (error) {
    logger.error("Failed to verify event:", error);
    throw error;
  }
}

/**
 * Configures secp256k1 with HMAC for WebSocket utilities
 * This is required for some WebSocket implementations
 * @example
 * configureHMAC();
 */
export function configureHMAC(): void {
  const hmacFunction = (
    key: Uint8Array,
    ...messages: Uint8Array[]
  ): Uint8Array => {
    const h = hmac.create(sha256, key);
    messages.forEach((msg) => h.update(msg));
    return h.digest();
  };

  const hmacSyncFunction = (
    key: Uint8Array,
    ...messages: Uint8Array[]
  ): Uint8Array => {
    const h = hmac.create(sha256, key);
    messages.forEach((msg) => h.update(msg));
    return h.digest();
  };

  // Type assertion to handle the utils property
  (secp256k1 as any).utils = {
    ...(secp256k1 as any).utils,
    hmacSha256: hmacFunction,
    hmacSha256Sync: hmacSyncFunction,
  };

  logger.debug("Configured HMAC for secp256k1");
  logger.debug(
    "secp256k1.utils after configuration:",
    (secp256k1 as any).utils,
  );
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
export async function createEvent(
  content: string,
  kind: number,
  privateKey: string,
  tags: string[][] = [],
): Promise<NostrEvent> {
  const publicKey = getPublicKey(hexToBytes(privateKey));

  const event: UnsignedEvent = {
    pubkey: publicKey,
    created_at: Math.floor(Date.now() / 1000),
    kind,
    tags,
    content,
  };

  const id = getEventHash(event);
  const sig = await signEvent(event, privateKey);

  logger.debug("Created new Nostr event");
  return {
    ...event,
    id,
    sig,
  };
}
