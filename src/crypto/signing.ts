import { sha256 } from "@noble/hashes/sha256";
import * as secp256k1 from "@noble/secp256k1";
import { UnsignedEvent } from "../types/events";
import { toHex, fromHex, utf8Encoder } from "../utils/encoding";
import { validatePrivateKey } from "../crypto/keys";

export class SigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SigningError';
  }
}

export async function createSignature(
  message: string | Uint8Array,
  privateKey: string
): Promise<string> {
  try {
    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }

    const messageBytes = typeof message === 'string' 
      ? utf8Encoder.encode(message)
      : message;
    
    const messageHash = sha256(messageBytes);
    const signatureObj = await secp256k1.sign(messageHash, privateKey);
    // Convert the signature to Uint8Array format
    const signatureBytes = new Uint8Array([...signatureObj.toCompactRawBytes(), signatureObj.recovery]);
    return toHex(signatureBytes);
  } catch (error) {
    if (error instanceof Error) {
      throw new SigningError(`Failed to create signature: ${error.message}`);
    }
    throw new SigningError('Failed to create signature: Unknown error');
  }
}

export async function verifySignature(
  message: string | Uint8Array,
  signature: string,
  publicKey: string
): Promise<boolean> {
  try {
    const messageBytes = typeof message === 'string'
      ? utf8Encoder.encode(message)
      : message;
    
    const messageHash = sha256(messageBytes);
    const signatureBytes = fromHex(signature);
    const publicKeyBytes = fromHex(publicKey);
    
    // Verify the signature
    return await secp256k1.verify(signatureBytes, messageHash, publicKeyBytes);
  } catch (error) {
    if (error instanceof Error) {
      throw new SigningError(`Failed to verify signature: ${error.message}`);
    }
    throw new SigningError('Failed to verify signature: Unknown error');
  }
}

/**
 * Sign a message using Schnorr signature
 * @param message - The message to sign
 * @param privateKey - The private key to sign with
 * @returns The signature as a hex string
 */
export async function schnorrSign(
  message: string | Uint8Array,
  privateKey: string
): Promise<string> {
  try {
    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }

    // Convert message to bytes if it's a string
    const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    
    // Hash the message
    const messageHash = sha256(messageBytes);
    
    // Sign the hash with schnorr
    const signatureBytes = await secp256k1.sign(messageHash, privateKey);
    return toHex(new Uint8Array(signatureBytes.toCompactRawBytes()));
  } catch (error) {
    throw new SigningError(`Failed to create Schnorr signature: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Verify a Schnorr signature
 * @param signature - The signature to verify (hex string)
 * @param message - The original message
 * @param publicKey - The public key to verify against
 * @returns True if the signature is valid
 */
export async function schnorrVerify(
  signature: string,
  message: string | Uint8Array,
  publicKey: string
): Promise<boolean> {
  try {
    // Convert message to bytes if it's a string
    const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    
    // Hash the message
    const messageHash = sha256(messageBytes);
    
    // Convert signature and public key to bytes
    const signatureBytes = fromHex(signature);
    const publicKeyBytes = fromHex(publicKey);
    
    // Verify the signature
    return await secp256k1.verify(signatureBytes, messageHash, publicKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Create an event signature using Schnorr signature
 * @param event - The unsigned event to sign
 * @param privateKey - The private key to sign with
 * @returns The signature as a hex string
 */
export async function createEventSignature(
  event: UnsignedEvent | string,
  privateKey: string
): Promise<string> {
  try {
    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }

    let messageBytes: Uint8Array;
    if (typeof event === 'string') {
      // If event is a string (eventId), convert it to bytes
      messageBytes = fromHex(event);
    } else {
      // If event is an UnsignedEvent, serialize it
      const serializedEvent = JSON.stringify([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
      ]);
      messageBytes = utf8Encoder.encode(serializedEvent);
    }
    
    return await schnorrSign(messageBytes, privateKey);
  } catch (error) {
    throw new SigningError(`Failed to create event signature: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}