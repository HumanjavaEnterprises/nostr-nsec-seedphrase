import {
  // Core functionality
  createUnsignedEvent,
  createNip01SignedEvent,
  validateUnsignedEvent,
  validateSignedEvent,
  validateEvent, 
  EventKind
} from '../index';

describe('Nostr NSEC Seedphrase Library', () => {
  const validPrivateKey = '7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a';
  const validPublicKey = '2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5c12';
  const validSeedPhrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  describe('Key Management', () => {
    // ... this section is fine ...
  });

  describe('Event Creation and Validation', () => {
    it('should create and validate unsigned events', async () => {
      const event = await createUnsignedEvent(
        'Hello, Nostr!',  // content
        EventKind.TEXT_NOTE,  // kind
        validPrivateKey,  // privateKey
        []  // tags
      );

      expect(await validateUnsignedEvent(event)).toBe(true);
    });

    it('should create and validate signed events', async () => {
      const event = await createNip01SignedEvent(
        validPublicKey,
        EventKind.TEXT_NOTE,
        'Hello, Nostr!',
        validPrivateKey
      );
    
      expect(await validateSignedEvent(event)).toBe(true);
    });
  }); 

  describe('NIP-19 Encoding', () => {
    // ... this section is fine ...
  });

  describe('NIP-13 Proof of Work', () => {
    // ... this section is fine ...
  });
}); 