// nip07.ts
import { UnsignedEvent, NostrEvent } from '../types/events';
import { getEventHash } from '../core/event';
import { schnorrSign, schnorrVerify } from '../crypto/signing';
import { getPublicKey } from '../crypto/keys';
import { encrypt, decrypt } from '../crypto/encryption';

/**
 * NIP-07: window.nostr capability for web browsers
 * @see https://github.com/nostr-protocol/nips/blob/master/07.md
 */

export interface NIP01Handler {
  getPublicKey(): Promise<string>;
  signEvent(event: UnsignedEvent): Promise<NostrEvent>;
}

export interface NIP04Handler {
  encrypt(pubkey: string, plaintext: string): Promise<string>;
  decrypt(pubkey: string, ciphertext: string): Promise<string>;
}

export interface NIP44Handler {
  signSchnorr(message: string): Promise<string>;
  verifySchnorr(signature: string, message: string, pubkey: string): Promise<boolean>;
}

export interface RelayHandler {
  getRelays(): Promise<{ [url: string]: { read: boolean; write: boolean } }>;
}

export interface NostrProvider extends NIP01Handler, NIP04Handler, NIP44Handler, RelayHandler {}

declare global {
  interface Window {
    nostr?: NostrProvider;
  }
}

export class NostrProviderImpl implements NostrProvider {
  private privateKey: string;

  constructor(privateKey: string) {
    if (!privateKey) {
      throw new Error('Provider requires a private key');
    }
    this.privateKey = privateKey;
  }

  // NIP-01: Basic Protocol Flow Handlers
  async getPublicKey(): Promise<string> {
    return getPublicKey(this.privateKey);
  }

  async signEvent(event: UnsignedEvent): Promise<NostrEvent> {
    const id = getEventHash(event);
    const sig = await schnorrSign(id, this.privateKey);
    
    return {
      ...event,
      id,
      sig,
    };
  }

  // NIP-04: Encrypted Direct Message
  async encrypt(pubkey: string, plaintext: string): Promise<string> {
    return encrypt(plaintext, this.privateKey, pubkey);
  }

  async decrypt(pubkey: string, ciphertext: string): Promise<string> {
    return decrypt(ciphertext, this.privateKey, pubkey);
  }

  // NIP-44: Schnorr Signatures
  async signSchnorr(message: string): Promise<string> {
    return schnorrSign(message, this.privateKey);
  }

  async verifySchnorr(
    signature: string,
    message: string,
    pubkey: string
  ): Promise<boolean> {
    return schnorrVerify(signature, message, pubkey);
  }

  // Relay Management
  async getRelays(): Promise<{ [url: string]: { read: boolean; write: boolean } }> {
    // Default relays - in a real implementation, this would be configurable
    return {
      'wss://relay.damus.io': { read: true, write: true },
      'wss://relay.nostr.info': { read: true, write: true },
    };
  }
}

/**
 * Initialize the window.nostr provider with a private key
 */
export function initializeProvider(key: string): void {
  if (typeof window !== 'undefined') {
    window.nostr = new NostrProviderImpl(key);
  }
}

/**
 * Get the window.nostr provider if available
 */
export function getNostrProvider(): NostrProvider | null {
  if (typeof window !== 'undefined' && window.nostr) {
    return window.nostr;
  }
  return null;
}

/**
 * Get public key from provider
 */
export async function getPublicKeyFromProvider(provider: NostrProvider): Promise<string> {
  return provider.getPublicKey();
}