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

export interface KeyPair {
  privateKey: string;
  publicKey: string;
  nsec: string;
  npub: string;
  seedPhrase: string;
}

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface UnsignedEvent {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

/**
 * Generate a new seed phrase
 */
export function generateSeedPhrase(): string {
  return generateMnemonic();
}

/**
 * Get entropy from seed phrase
 */
export function getEntropyFromSeedPhrase(seedPhrase: string): string {
  if (!validateMnemonic(seedPhrase)) {
    throw new Error("Invalid seed phrase");
  }
  const entropy = mnemonicToEntropy(seedPhrase);
  return entropy;
}

/**
 * Validate a seed phrase
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
 * Convert a seed phrase to a key pair
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
 * Generate a new key pair with a seed phrase
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
 * Create a key pair from a hex private key
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
 * Convert nsec to hex format
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
 * Convert npub to hex format
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
 * Convert hex to npub format
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
 * Convert hex to nsec format
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
 * Sign a message with a private key
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
 * Verify a message signature
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
 * Sign a Nostr event
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
 * Verify a Nostr event signature
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
 * Configure secp256k1 with HMAC for WebSocket utilities
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
 * Create a new Nostr event
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
