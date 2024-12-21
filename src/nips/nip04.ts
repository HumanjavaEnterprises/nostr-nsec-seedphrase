import { encrypt as encryptMessage, decrypt as decryptMessage, EncryptionError } from '../crypto/encryption';
import { validatePrivateKey, validatePublicKey, getPublicKey } from '../crypto/keys';
import { UnsignedEvent } from '../types/events';
import { createNip01SignedEvent } from './nip01';

/**
 * Create an encrypted direct message event (NIP-04)
 * @param content - The message content to encrypt
 * @param privateKey - The sender's private key
 * @param recipientPubKey - The recipient's public key
 * @returns The encrypted event
 */
export async function createEncryptedDirectMessage(
  content: string,
  privateKey: string,
  recipientPubKey: string
): Promise<UnsignedEvent> {
  try {
    if (typeof content !== 'string') {
      throw new EncryptionError('Content must be a string');
    }

    if (!validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }
    if (!validatePublicKey(recipientPubKey)) {
      throw new Error('Invalid public key');
    }

    const encryptedContent = await encryptMessage(content, privateKey, recipientPubKey);
    const senderPubKey = getPublicKey(privateKey);
    
    return {
      kind: 4,
      pubkey: senderPubKey,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['p', recipientPubKey]],
      content: encryptedContent,
    };
  } catch (error) {
    throw new EncryptionError(`Failed to create encrypted direct message: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

// Re-export the encryption functions from the global crypto module
export { encryptMessage as encrypt, decryptMessage as decrypt };