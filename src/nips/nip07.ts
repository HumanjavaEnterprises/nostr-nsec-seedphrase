// nip07.ts
import { validatePrivateKey } from '../crypto/keys';
import { schnorrSign, schnorrVerify, createEventSignature } from '../crypto/signing';
import { encrypt, decrypt } from '../nips/nip04';
import { UnsignedEvent } from '../types/events';
import { createNip01SignedEvent } from '../nips/nip01';

let privateKey: string | null = null;

/**
 * Initialize the Nostr provider with a private key
 */
export function initializeProvider(key: string) {
  if (!validatePrivateKey(key)) {
    throw new Error('Invalid private key');
  }
  privateKey = key;
}

/**
 * Get the Nostr provider implementation
 * @throws Error if provider is not initialized with a private key
 */
export interface INostrProvider {
  getPublicKey(): Promise<string>;
  signEvent(event: UnsignedEvent): Promise<any>;
  getRelays(): Promise<Record<string, { read: boolean; write: boolean }>>;
  signSchnorr(message: string): Promise<string>;
  encrypt(recipientPubKey: string, content: string): Promise<string>;
  decrypt(senderPubKey: string, content: string): Promise<string>;
  nip04: {
    encrypt(pubkey: string, plaintext: string): Promise<string>;
    decrypt(pubkey: string, ciphertext: string): Promise<string>;
  };
}

export class NostrProviderImpl implements INostrProvider {
  private privateKey: string;

  constructor(privateKey: string) {
    if (!privateKey || !validatePrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }
    this.privateKey = privateKey;
  }

  async getPublicKey(): Promise<string> {
    // TODO: implement getPublicKey
    throw new Error('Not implemented');
  }

  async signEvent(event: UnsignedEvent): Promise<any> {
    return createEventSignature(event, this.privateKey);
  }

  async getRelays(): Promise<Record<string, { read: boolean; write: boolean }>> {
    return {
      'wss://relay.nostr.info': { read: true, write: true },
      'wss://nostr-pub.wellorder.net': { read: true, write: true }
    };
  }

  async signSchnorr(message: string): Promise<string> {
    return await schnorrSign(message, this.privateKey);
  }

  nip04 = {
    encrypt: async (pubkey: string, plaintext: string): Promise<string> => {
      return encrypt(this.privateKey, pubkey, plaintext);
    },
    decrypt: async (pubkey: string, ciphertext: string): Promise<string> => {
      return decrypt(this.privateKey, pubkey, ciphertext);
    }
  };

  async encrypt(recipientPubKey: string, content: string): Promise<string> {
    return encrypt(this.privateKey, recipientPubKey, content);
  }

  async decrypt(senderPubKey: string, content: string): Promise<string> {
    return decrypt(this.privateKey, senderPubKey, content);
  }
}

export const getProvider = (): INostrProvider => {
  if (!privateKey) {
    throw new Error('Provider not initialized. Call initializeProvider first.');
  }
  return new NostrProviderImpl(privateKey);
};

export interface NostrEvent extends UnsignedEvent {
  sig: string;
}

export interface RelayPolicy {
  read: boolean;
  write: boolean;
}