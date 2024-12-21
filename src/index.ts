/**
 * Main entry point for the nostr-nsec-seedphrase library.
 * Provides core functionality and NIP implementations.
 */
import { pino } from 'pino';

// Initialize crypto setup first
import './core/setup';

// Configure logging
export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  name: 'nostr-nsec-seedphrase',
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true
    }
  }
});

// Export types
export {
  NostrEvent,
  UnsignedEvent,
  EventKind,
  EventValidationResult
} from './types';

// Export core functionality
export * from './utils/encoding';
export * from './crypto/keys';
export { encrypt, decrypt } from './crypto/encryption';
export { schnorrSign, schnorrVerify, createEventSignature } from './crypto/signing';
export { 
  validateSignedEvent, 
  validateEvent,
  createUnsignedEventFromPubkey as createUnsignedEvent 
} from './core/event';
export { validateUnsignedEvent } from './core/validation';

// Export NIP implementations
export * from './nips/nip01';
export * from './nips/nip04';  
export * from './nips/nip06';
export * from './nips/nip07';
export * from './nips/nip13';
export * from './nips/nip19';
export * from './nips/nip26';
export * from './nips/nip39';
export * from './nips/nip44';
export * from './nips/nip47';
export * from './nips/nip49';