import { generateMnemonic, validateMnemonic, mnemonicToEntropy } from "bip39";
import * as secp256k1 from "@noble/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { bech32 } from "bech32";
import { logger } from "./utils/logger";

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
 * @returns {Uint8Array} The entropy value
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const entropy = getEntropyFromSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(entropy); // Uint8Array
 */
export function getEntropyFromSeedPhrase(seedPhrase: string): Uint8Array {
  if (!validateMnemonic(seedPhrase)) {
    throw new Error("Invalid seed phrase");
  }
  // bip39.mnemonicToEntropy returns a hex string, convert it to Uint8Array
  const entropyHex = mnemonicToEntropy(seedPhrase);
  return hexToBytes(entropyHex);
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
  logger.log({ seedPhrase }, "Validating seed phrase");
  logger.log({ seedPhrase }, "Input being validated");
  const isValid = validateMnemonic(seedPhrase);
  logger.log({ isValid }, "Validated seed phrase");
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
export function seedPhraseToKeyPair(seedPhrase: string): KeyPair {
  try {
    const entropy = getEntropyFromSeedPhrase(seedPhrase);
    // Hash the entropy to generate a proper private key
    const privateKeyBytes = sha256(entropy);
    const privateKeyHex = bytesToHex(privateKeyBytes);

    // Derive the public key
    const publicKeyBytes = secp256k1.getPublicKey(privateKeyHex, true); // Force compressed format
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
  } catch (error) {
    logger.error(
      "Failed to create key pair from seed phrase:",
      error?.toString(),
    );
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
export function fromHex(privateKeyHex: string): KeyPair {
  try {
    // Validate the private key
    const privateKeyBytes = hexToBytes(privateKeyHex);
    if (!secp256k1.utils.isValidPrivateKey(privateKeyBytes)) {
      throw new Error("Invalid private key");
    }

    // Derive the public key
    const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes, true); // Force compressed format
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
  } catch (error) {
    logger.error("Failed to create key pair from hex:", error?.toString());
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
export function getPublicKey(privateKey: string): string {
  try {
    const privateKeyBytes = hexToBytes(privateKey);
    const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes, true); // Force compressed format
    return bytesToHex(publicKeyBytes);
  } catch (error) {
    logger.error("Failed to get public key:", error?.toString());
    throw error;
  }
}

/**
 * NIP-19 encoding and decoding functions
 * @namespace
 */
export const nip19 = {
  /**
   * Encodes a public key into npub format
   * @param {string} pubkey - The hex-encoded public key
   * @returns {string} The bech32-encoded npub string
   */
  npubEncode(pubkey: string): string {
    const data = hexToBytes(pubkey);
    const words = bech32.toWords(Uint8Array.from(data));
    return bech32.encode("npub", words, 1000);
  },

  /**
   * Decodes an npub string to hex format
   * @param {string} npub - The bech32-encoded npub string
   * @returns {string} The hex-encoded public key
   */
  npubDecode(npub: string): string {
    const { prefix, words } = bech32.decode(npub, 1000);
    if (prefix !== "npub") throw new Error("Invalid npub: wrong prefix");
    const data = bech32.fromWords(words);
    return bytesToHex(
      data instanceof Uint8Array ? data : Uint8Array.from(data),
    );
  },

  /**
   * Encodes a private key into nsec format
   * @param {string} privkey - The hex-encoded private key
   * @returns {string} The bech32-encoded nsec string
   */
  nsecEncode(privkey: string): string {
    const data = hexToBytes(privkey);
    const words = bech32.toWords(Uint8Array.from(data));
    return bech32.encode("nsec", words, 1000);
  },

  /**
   * Decodes an nsec string to hex format
   * @param {string} nsec - The bech32-encoded nsec string
   * @returns {string} The hex-encoded private key
   */
  nsecDecode(nsec: string): string {
    const { prefix, words } = bech32.decode(nsec, 1000);
    if (prefix !== "nsec") throw new Error("Invalid nsec: wrong prefix");
    const data = bech32.fromWords(words);
    return bytesToHex(
      data instanceof Uint8Array ? data : Uint8Array.from(data),
    );
  },

  /**
   * Encodes an event ID into note format
   * @param {string} eventId - The hex-encoded event ID
   * @returns {string} The bech32-encoded note string
   */
  noteEncode(eventId: string): string {
    const data = hexToBytes(eventId);
    const words = bech32.toWords(Uint8Array.from(data));
    return bech32.encode("note", words, 1000);
  },

  /**
   * Decodes a note string to hex format
   * @param {string} note - The bech32-encoded note string
   * @returns {string} The hex-encoded event ID
   */
  noteDecode(note: string): string {
    const { prefix, words } = bech32.decode(note, 1000);
    if (prefix !== "note") throw new Error("Invalid note: wrong prefix");
    const data = bech32.fromWords(words);
    return bytesToHex(
      data instanceof Uint8Array ? data : Uint8Array.from(data),
    );
  },

  /**
   * Decodes any bech32-encoded Nostr entity
   * @param {string} bech32str - The bech32-encoded string
   * @returns {{ type: string; data: Uint8Array }} Object containing the decoded type and data
   * @property {string} type - The type of the decoded entity (npub, nsec, or note)
   * @property {Uint8Array} data - The raw decoded data
   */
  decode(bech32str: string): { type: string; data: Uint8Array } {
    const { prefix, words } = bech32.decode(bech32str, 1000);
    const data = bech32.fromWords(words);
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
function getEventHash(event: UnsignedEvent): string {
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
    logger.log("Event signed successfully");
    return bytesToHex(signature.toCompactRawBytes());
  } catch (error) {
    logger.error("Failed to sign event:", error?.toString());
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
      logger.log("Invalid event: missing required fields");
      return false;
    }

    const hash = getEventHash(event);
    if (hash !== event.id) {
      logger.log("Event hash mismatch");
      return false;
    }

    logger.log("Verifying event signature");
    return await secp256k1.verify(
      hexToBytes(event.sig),
      hexToBytes(hash),
      hexToBytes(event.pubkey),
    );
  } catch (error) {
    logger.error("Failed to verify event:", error?.toString());
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

  logger.log("Configured HMAC for secp256k1");
  logger.log("secp256k1.utils after configuration:", (secp256k1 as any).utils);
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
  const publicKey = getPublicKey(privateKey);

  const event: UnsignedEvent = {
    pubkey: publicKey,
    created_at: Math.floor(Date.now() / 1000),
    kind,
    tags,
    content,
  };

  const id = getEventHash(event);
  const sig = await signEvent(event, privateKey);

  logger.log("Created new Nostr event");
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
export function seedPhraseToPrivateKey(seedPhrase: string): string {
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
export function privateKeyToNsec(privateKey: string): string {
  try {
    return nip19.nsecEncode(privateKey);
  } catch (error) {
    logger.error("Failed to encode nsec:", error?.toString());
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
export function privateKeyToNpub(privateKey: string): string {
  try {
    const privateKeyBytes = hexToBytes(privateKey);
    const publicKey = secp256k1.getPublicKey(privateKeyBytes, true);
    return nip19.npubEncode(bytesToHex(publicKey));
  } catch (error) {
    logger.error("Failed to encode npub:", error?.toString());
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
    const hexPrivateKey = nip19.nsecDecode(nsec);
    logger.log("Converted nsec to hex");
    return hexPrivateKey;
  } catch (error) {
    logger.error("Failed to decode nsec:", error?.toString());
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
    logger.log("Converted npub to hex");
    return bytesToHex(data);
  } catch (error) {
    logger.error("Failed to decode npub:", error?.toString());
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
    logger.log("Converting hex to npub");
    return nip19.npubEncode(publicKeyHex);
  } catch (error) {
    logger.error("Failed to encode npub:", error?.toString());
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
    logger.log("Converting hex to nsec");
    return nip19.nsecEncode(privateKeyHex);
  } catch (error) {
    logger.error("Failed to encode nsec:", error?.toString());
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
    logger.log("Message signed successfully");
    return bytesToHex(signature.toCompactRawBytes());
  } catch (error) {
    logger.error("Failed to sign message:", error?.toString());
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
    logger.log("Verifying message signature");
    return await secp256k1.verify(
      hexToBytes(signature),
      messageHash,
      hexToBytes(publicKey),
    );
  } catch (error) {
    logger.error("Failed to verify signature:", error?.toString());
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
export function nsecToPrivateKey(nsec: string): string {
  try {
    return nip19.nsecDecode(nsec);
  } catch (error) {
    logger.error("Failed to decode nsec:", error?.toString());
    throw error;
  }
}
