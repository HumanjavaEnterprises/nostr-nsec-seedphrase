import { getPublicKey, nip19, getEventHash } from 'nostr-tools';
import * as secp256k1 from '@noble/secp256k1';
import * as bip39 from 'bip39';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';

export interface KeyPair {
  privateKey: string;
  publicKey: string;
  nsec: string;
  npub: string;
}

export interface KeyPairWithSeed extends KeyPair {
  seedPhrase: string;
}

export interface NostrEvent {
  id?: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig?: string;
}

/**
 * Generate a new seed phrase
 */
export function generateSeedPhrase(): string {
  const entropy = secp256k1.utils.randomPrivateKey();
  return bip39.entropyToMnemonic(bytesToHex(entropy));
}

/**
 * Convert a seed phrase to entropy which can be used as a private key
 */
export function seedPhraseToEntropy(seedPhrase: string): string {
  if (!validateSeedPhrase(seedPhrase)) {
    throw new Error('Invalid seed phrase');
  }
  const entropy = bip39.mnemonicToEntropy(seedPhrase);
  return entropy;
}

/**
 * Validate a seed phrase
 */
export function validateSeedPhrase(seedPhrase: string): boolean {
  return bip39.validateMnemonic(seedPhrase);
}

/**
 * Convert a seed phrase to a key pair
 */
export function seedPhraseToKeyPair(seedPhrase: string): KeyPair {
  const privateKey = seedPhraseToEntropy(seedPhrase);
  const publicKey = getPublicKey(hexToBytes(privateKey));
  const nsec = nip19.nsecEncode(hexToBytes(privateKey));
  const npub = nip19.npubEncode(publicKey);
  
  return {
    privateKey,
    publicKey,
    nsec,
    npub
  };
}

/**
 * Generate a new Nostr key pair with corresponding seed phrase
 */
export function generateKeyPairWithSeed(): KeyPairWithSeed {
  try {
    const privateKeyBytes = secp256k1.utils.randomPrivateKey();
    const privateKey = bytesToHex(privateKeyBytes);
    const nsec = nip19.nsecEncode(privateKeyBytes);
    const publicKey = getPublicKey(privateKeyBytes);
    const npub = nip19.npubEncode(publicKey);
    const seedPhrase = bip39.entropyToMnemonic(privateKey);

    return {
      privateKey,
      publicKey,
      nsec,
      npub,
      seedPhrase
    };
  } catch (error) {
    throw new Error(`Failed to generate new key pair: ${(error as Error).message}`);
  }
}

/**
 * Create a key pair from a hex private key
 */
export function fromHex(privateKeyHex: string): KeyPair {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error('Invalid hex private key format. Must be 64 characters of hex.');
    }

    const nsec = nip19.nsecEncode(hexToBytes(privateKeyHex));
    const publicKey = getPublicKey(hexToBytes(privateKeyHex));
    const npub = nip19.npubEncode(publicKey);

    return {
      privateKey: privateKeyHex,
      publicKey,
      nsec,
      npub
    };
  } catch (error) {
    throw new Error(`Failed to create key pair from hex: ${(error as Error).message}`);
  }
}

/**
 * Convert an nsec to its hex representation
 */
export function nsecToHex(nsec: string): string {
  try {
    const { type, data } = nip19.decode(nsec);
    if (type !== 'nsec') {
      throw new Error('Invalid nsec format');
    }
    return bytesToHex(data as Uint8Array);
  } catch (error) {
    throw new Error(`Failed to convert nsec to hex: ${(error as Error).message}`);
  }
}

/**
 * Convert an npub to its hex representation
 */
export function npubToHex(npub: string): string {
  try {
    const { type, data } = nip19.decode(npub);
    if (type !== 'npub') {
      throw new Error('Invalid npub format');
    }
    return data as string;
  } catch (error) {
    throw new Error(`Failed to convert npub to hex: ${(error as Error).message}`);
  }
}

/**
 * Convert a hex public key to npub format
 */
export function hexToNpub(publicKeyHex: string): string {
  try {
    return nip19.npubEncode(publicKeyHex);
  } catch (error) {
    throw new Error(`Failed to convert hex to npub: ${(error as Error).message}`);
  }
}

/**
 * Convert a hex private key to nsec format
 */
export function hexToNsec(privateKeyHex: string): string {
  try {
    return nip19.nsecEncode(hexToBytes(privateKeyHex));
  } catch (error) {
    throw new Error(`Failed to convert hex to nsec: ${(error as Error).message}`);
  }
}

/**
 * Sign a message with a private key
 */
export async function signMessage(message: string, privateKey: string): Promise<string> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    const signature = await secp256k1.sign(messageHash, hexToBytes(privateKey));
    return signature.toDERHex();
  } catch (error) {
    throw new Error(`Failed to sign message: ${(error as Error).message}`);
  }
}

/**
 * Verify a message signature
 */
export async function verifySignature(
  message: string,
  signature: string,
  publicKey: string
): Promise<boolean> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const messageHash = sha256(messageBytes);
    return secp256k1.verify(signature, messageHash, hexToBytes(publicKey));
  } catch (error) {
    throw new Error(`Failed to verify signature: ${(error as Error).message}`);
  }
}

/**
 * Sign a Nostr event
 */
export function signEvent(event: NostrEvent, privateKey: string): string {
  try {
    if (!event.pubkey || !event.created_at || event.kind === undefined || !event.content) {
      throw new Error('Invalid event: missing required fields');
    }

    const eventHash = getEventHash(event);
    const signatureBytes = secp256k1.signSync(
      hexToBytes(eventHash),
      hexToBytes(privateKey)
    );
    return bytesToHex(signatureBytes);
  } catch (error) {
    throw new Error(`Failed to sign event: ${(error as Error).message}`);
  }
}

/**
 * Verify a Nostr event signature
 */
export function verifyEvent(event: NostrEvent): boolean {
  try {
    if (!event.id || !event.pubkey || !event.sig) {
      throw new Error('Invalid event: missing required fields');
    }

    const hash = getEventHash(event);
    if (hash !== event.id) {
      return false;
    }

    return secp256k1.verifySync(
      hexToBytes(event.sig),
      hexToBytes(hash),
      hexToBytes(event.pubkey)
    );
  } catch (error) {
    throw new Error(`Failed to verify event: ${(error as Error).message}`);
  }
}

/**
 * Configure secp256k1 with HMAC for WebSocket utilities
 */
export function configureHMAC(): void {
  secp256k1.utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
    const h = hmac.create(sha256, key);
    messages.forEach(msg => h.update(msg));
    return h.digest();
  };
}

/**
 * Create a Nostr event
 */
export function createEvent(
  content: string,
  kind: number,
  privateKey: string,
  tags: string[][] = []
): NostrEvent {
  const publicKey = getPublicKey(hexToBytes(privateKey));
  const event: NostrEvent = {
    pubkey: publicKey,
    created_at: Math.floor(Date.now() / 1000),
    kind,
    tags,
    content
  };

  event.id = getEventHash(event);
  event.sig = signEvent(event, privateKey);
  return event;
}
