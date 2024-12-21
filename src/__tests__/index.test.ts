import {
  // Core functionality
  createUnsignedEvent,
  createNip01SignedEvent,
  validateUnsignedEvent,
  validateSignedEvent,
  validateEvent, 
  EventKind,
  validatePrivateKey,
  validatePublicKey,
  npubEncode,
  npubDecode,
  nsecEncode,
  nsecDecode,
  generateProofOfWork,
  hasValidProofOfWork
} from '../index';

describe('Nostr NSEC Seedphrase Library', () => {
  // Using the TEST_CONSTANTS from test-utils
  const _validPrivateKey = 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35';
  const _validPublicKey = '02e755ea8675f7a092ac4ae1f3c3e0ad6d82744d3da0f5f7049eaa5b0adc3ea543';
  const _validSeedPhrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  describe('Key Management', () => {
    it('should validate generated keys', () => {
      const privateKey = _validPrivateKey;
      const publicKey = _validPublicKey;
      expect(validatePrivateKey(privateKey)).toBe(true);
      expect(validatePublicKey(publicKey)).toBe(true);
    });
  });

  describe('Event Creation and Validation', () => {
    it('should create and validate unsigned events', async () => {
      const event = await createUnsignedEvent(
        'Hello, Nostr!',  // content
        EventKind.TEXT_NOTE,  // kind
        _validPrivateKey,  // privateKey
        []  // tags
      );

      const validation = await validateUnsignedEvent(event);
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should create and validate signed events', async () => {
      const event = await createNip01SignedEvent(
        _validPublicKey,
        EventKind.TEXT_NOTE,
        'Hello, Nostr!',
        _validPrivateKey
      );
    
      const validation = await validateSignedEvent(event);
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });
  }); 

  describe('NIP-19 Encoding', () => {
    it('should encode and decode npub format', () => {
      const npub = npubEncode(_validPublicKey);
      expect(npub).toBeDefined();
      expect(npub.startsWith('npub1')).toBe(true);
      const decoded = npubDecode(npub);
      expect(decoded.toLowerCase()).toBe(_validPublicKey.toLowerCase());
    });

    it('should encode and decode nsec format', () => {
      const nsec = nsecEncode(_validPrivateKey);
      expect(nsec).toBeDefined();
      expect(nsec.startsWith('nsec1')).toBe(true);
      const decoded = nsecDecode(nsec);
      expect(decoded.toLowerCase()).toBe(_validPrivateKey.toLowerCase());
    });
  });

  describe('NIP-13 Proof of Work', () => {
    it('should generate valid proof of work', async () => {
      const event = {
        pubkey: _validPublicKey,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello, Nostr!'
      };
      const difficulty = 0; // Use zero difficulty for quick test
      const eventWithPow = await generateProofOfWork(event, difficulty);
      expect(eventWithPow).toBeDefined();
      expect(eventWithPow.nonce).toBeDefined();
      expect(hasValidProofOfWork(eventWithPow, difficulty)).toBe(true);
    });
  });
}); 