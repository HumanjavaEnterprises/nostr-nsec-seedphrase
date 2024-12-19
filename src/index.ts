/**
 * Main entry point for the nostr-nsec-seedphrase library.
 * Provides core functionality and NIP implementations.
 */
import { pino } from 'pino';

// Configure logging
export const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true
    }
  }
});

// Core functionality
export { createUnsignedEvent, createSignedEvent, EventCreationError } from './core/event';
export { DelegationConditions, isDelegationValid, validateUnsignedEvent, validateSignedEvent, validateEvent } from './core/validation';

// Cryptographic utilities
export * from './crypto/keys';
export * from './crypto/signing';
export { encrypt, decrypt } from './crypto/encryption';

// NIPs implementation
export { verifyEventSignature, createNip01SignedEvent } from './nips/nip01';
export { createEncryptedDirectMessage } from './nips/nip04';  // Only export what's unique to NIP-04
export { seedPhraseToKeyPair, generateKeyPairWithSeed, keyPairFromPrivateKey } from './nips/nip06';
export * from './nips/nip07';
export * from './nips/nip13';
export * from './nips/nip19';
export * from './nips/nip26';
export * from './nips/nip39';
export * from './nips/nip44';
export * from './nips/nip47';
export * from './nips/nip49';

// Utility functions
export * from './utils/encoding';

// Types
export * from './types';