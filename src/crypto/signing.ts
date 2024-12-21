import { sha256 } from "@noble/hashes/sha256";
import * as secp256k1 from "@noble/secp256k1";
import { UnsignedEvent } from "../types/events";
import { toHex, fromHex, utf8Encoder } from "../utils/encoding";
import { validatePrivateKey, validatePublicKey } from "../crypto/keys";

export class SigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SigningError';
  }
}

// Initialize secp256k1 with precomputes for better performance
secp256k1.utils.precompute();

/**
 * Sign a message using Schnorr signature (Nostr standard)
 * @param message - The message to sign (hex string)
 * @param privateKey - The private key to sign with (hex string)
 * @returns The signature as a hex string
 */
export async function schnorrSign(
  message: string,
  privateKey: string
): Promise<string> {
  try {
    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }

    const messageBytes = fromHex(message);
    const privateKeyBytes = fromHex(privateKey);
    
    const signature = await secp256k1.schnorrSign(messageBytes, privateKeyBytes);
    return toHex(signature);
  } catch (error) {
    throw new SigningError(`Failed to create Schnorr signature: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Verify a Schnorr signature (Nostr standard)
 * @param signature - The signature to verify (hex string)
 * @param message - The original message (hex string)
 * @param publicKey - The public key to verify against (hex string)
 * @returns True if the signature is valid
 */
export async function schnorrVerify(
  signature: string,
  message: string,
  publicKey: string
): Promise<boolean> {
  try {
    if (!validatePublicKey(publicKey)) {
      throw new Error('Invalid public key');
    }

    const signatureBytes = fromHex(signature);
    const messageBytes = fromHex(message);
    const publicKeyBytes = fromHex(publicKey);

    return await secp256k1.schnorrVerify(signatureBytes, messageBytes, publicKeyBytes);
  } catch (error) {
    throw new SigningError(`Failed to verify Schnorr signature: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Create a signature for a Nostr event
 * @param event - The unsigned event to sign
 * @param privateKey - The private key to sign with (hex string)
 * @returns The signature as a hex string
 */
export async function createEventSignature(
  event: UnsignedEvent | string,
  privateKey: string
): Promise<string> {
  try {
    let serializedEvent: string;
    
    if (typeof event === 'string') {
      serializedEvent = event;
    } else {
      // Serialize the event according to Nostr spec
      const serializedArray = [
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
      ];
      serializedEvent = JSON.stringify(serializedArray);
    }

    // Create SHA256 hash of the serialized event
    const eventHash = sha256(utf8Encoder.encode(serializedEvent));
    
    // Sign the hash using Schnorr
    return await schnorrSign(toHex(eventHash), privateKey);
  } catch (error) {
    throw new SigningError(`Failed to create event signature: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}