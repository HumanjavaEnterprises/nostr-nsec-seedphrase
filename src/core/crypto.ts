import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import logger from "../utils/logger.js";
import type { ValidationResult } from "../types/keys.js";
import type { NostrEvent, UnsignedEvent } from "../types/events.js";

/**
 * Signs a message with a private key
 * @param {string} message - Message to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} Signature in hex format
 */
export async function sign(
  message: string,
  privateKey: string,
): Promise<string> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    const messageHashHex = bytesToHex(messageHash);
    const signature = await schnorr.sign(messageHashHex, privateKey);
    return bytesToHex(signature);
  } catch (error) {
    logger.error("Failed to sign message:", error?.toString());
    throw new Error("Failed to sign message");
  }
}

/**
 * Verifies a signature
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verify(
  signature: string,
  message: string,
  publicKey: string,
): Promise<boolean> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    const messageHashHex = bytesToHex(messageHash);
    const isValid = await schnorr.verify(
      hexToBytes(signature),
      messageHashHex,
      hexToBytes(publicKey),
    );
    return isValid;
  } catch (error) {
    logger.error("Failed to verify signature:", error?.toString());
    return false;
  }
}

/**
 * Verifies a signature and returns a detailed result
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<ValidationResult>} Validation result with details
 */
export async function verifyWithResult(
  signature: string,
  message: string,
  publicKey: string,
): Promise<ValidationResult> {
  try {
    const isValid = await verify(signature, message, publicKey);
    return {
      isValid,
      error: isValid ? undefined : "Invalid signature",
    };
  } catch (error) {
    logger.error("Failed to verify with result:", error?.toString());
    return {
      isValid: false,
      error: error?.toString() || "Unknown error",
    };
  }
}

/**
 * Derives a shared secret using ECDH
 * @param {string} privateKey - Private key in hex format
 * @param {string} publicKey - Public key in hex format (32-byte x-only Nostr pubkey)
 * @returns {Promise<Uint8Array>} Shared secret bytes (x-coordinate of the shared point)
 */
export async function getSharedSecret(
  privateKey: string,
  publicKey: string,
): Promise<Uint8Array> {
  try {
    const privKeyBytes = hexToBytes(privateKey);
    // Nostr uses 32-byte x-only pubkeys; prefix with '02' for compressed format
    const sharedPoint = secp256k1.getSharedSecret(privKeyBytes, '02' + publicKey);
    // Extract x-coordinate only (bytes 1..33), per Nostr NIP-04 convention
    const sharedX = sharedPoint.slice(1, 33);
    privKeyBytes.fill(0); // zero sensitive material
    return sharedX;
  } catch (error) {
    logger.error("Failed to get shared secret:", error?.toString());
    throw new Error("Failed to get shared secret");
  }
}

/**
 * Synchronously computes HMAC-SHA256
 * @param {Uint8Array} key - Key bytes
 * @param {Uint8Array} message - Message bytes
 * @returns {Uint8Array} HMAC bytes
 */
export function hmacSha256Sync(
  key: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  return hmac.create(sha256, key).update(message).digest();
}

/**
 * Asynchronously computes HMAC-SHA256
 * @param {Uint8Array} key - Key bytes
 * @param {Uint8Array} message - Message bytes
 * @returns {Promise<Uint8Array>} HMAC bytes
 */
export async function hmacSha256Async(
  key: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  return hmacSha256Sync(key, message);
}

/**
 * Calculates the event hash/ID according to the Nostr protocol
 * @param {UnsignedEvent} event - The unsigned event to hash
 * @returns {string} The event hash in hex format
 */
export function getEventHash(event: UnsignedEvent): string {
  try {
    const serialized = JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content,
    ]);
    const hash = sha256(new TextEncoder().encode(serialized));
    return bytesToHex(hash);
  } catch (error) {
    logger.error("Failed to get event hash:", error?.toString());
    throw new Error("Failed to get event hash");
  }
}

/**
 * Signs an event with a private key
 * @param {UnsignedEvent} event - The unsigned event to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} The signature in hex format
 */
export async function signEvent(
  event: UnsignedEvent,
  privateKey: string,
): Promise<string> {
  try {
    const eventHash = getEventHash(event);
    const sig = await schnorr.sign(eventHash, privateKey);
    return bytesToHex(sig);
  } catch (error) {
    logger.error("Failed to sign event:", error?.toString());
    throw new Error("Failed to sign event");
  }
}

/**
 * Verifies an event signature
 * @param {NostrEvent} event - The signed event to verify
 * @returns {Promise<boolean>} True if the signature is valid
 */
export async function verifyEvent(event: NostrEvent): Promise<boolean> {
  try {
    const hash = getEventHash({
      pubkey: event.pubkey,
      created_at: event.created_at,
      kind: event.kind,
      tags: event.tags,
      content: event.content,
    });

    return schnorr.verify(
      hexToBytes(event.sig),
      hash,
      hexToBytes(event.pubkey),
    );
  } catch (error) {
    logger.error("Failed to verify event:", error?.toString());
    return false;
  }
}

/**
 * Signs a message with a private key
 * @param {string} message - Message to sign
 * @param {string} privateKey - Private key in hex format
 * @returns {Promise<string>} The signature in hex format
 */
export async function signMessage(
  message: string,
  privateKey: string,
): Promise<string> {
  try {
    const messageHash = sha256(new TextEncoder().encode(message));
    const messageHashHex = bytesToHex(messageHash);
    const sig = await schnorr.sign(messageHashHex, privateKey);
    return bytesToHex(sig);
  } catch (error) {
    logger.error("Failed to sign message:", error?.toString());
    throw new Error("Failed to sign message");
  }
}

/**
 * Verifies a message signature
 * @param {string} signature - Signature in hex format
 * @param {string} message - Original message that was signed
 * @param {string} publicKey - Public key in hex format
 * @returns {Promise<boolean>} True if the signature is valid
 */
export async function verifyMessage(
  signature: string,
  message: string,
  publicKey: string,
): Promise<boolean> {
  try {
    const messageHash = sha256(new TextEncoder().encode(message));
    const messageHashHex = bytesToHex(messageHash);
    return await schnorr.verify(
      hexToBytes(signature),
      messageHashHex,
      hexToBytes(publicKey),
    );
  } catch (error) {
    logger.error("Failed to verify message:", error?.toString());
    return false;
  }
}

/**
 * Configures the HMAC functions for schnorr
 */
export function configureHMAC(): void {
  try {
    (schnorr.utils as any).hmacSha256Sync = hmacSha256Sync;
    (schnorr.utils as any).hmacSha256Async = hmacSha256Async;
  } catch (error) {
    logger.error("Failed to configure HMAC:", error?.toString());
    throw new Error("Failed to configure HMAC");
  }
}
