import { getPublicKey } from '../crypto/keys';
import {
  encrypt,
  decrypt,
  createEncryptedMessage,
  EncryptionError
} from '../crypto/encryption';
import { UnsignedEvent } from '../types/events';
import { createNip01SignedEvent } from './nip01';

/**
 * Create an encrypted direct message event (NIP-04)
 * @param content - The message content to encrypt
 * @param privateKey - The sender's private key
 * @param recipientPubKey - The recipient's public key
 * @returns A signed event containing the encrypted message
 */
export async function createEncryptedDirectMessage(
  content: string,
  privateKey: string,
  recipientPubKey: string
): Promise<UnsignedEvent> {
  try {
    const encryptedContent = await createEncryptedMessage(content, privateKey, recipientPubKey);
    const senderPubKey = getPublicKey(privateKey);
    
    // Create the "p" tag for the recipient's public key
    const tags = [['p', recipientPubKey]];
    
    // Create and return a signed event
    return await createNip01SignedEvent(
      senderPubKey,
      4, // kind 4 is encrypted direct message
      encryptedContent,
      privateKey,
      tags
    );
  } catch (error) {
    throw new EncryptionError(`Failed to create encrypted direct message: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

// Re-export encryption functions
export { encrypt, decrypt, createEncryptedMessage, EncryptionError };