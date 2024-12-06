import { NostrSeedPhrase } from '../index';

// Mock crypto for tests
const mockCrypto = {
  getRandomValues: (arr: Uint8Array) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  }
};
global.crypto = mockCrypto as unknown as Crypto;

describe('NostrSeedPhrase', () => {
  // Generate a valid key pair for testing
  const initial = NostrSeedPhrase.generateNew();
  const testNsec = initial.nsec;
  const testSeed = NostrSeedPhrase.nsecToSeed(testNsec);
  const testMnemonic = testSeed.seedPhrase;

  describe('nsecToSeed', () => {
    it('should convert nsec to mnemonic', () => {
      const result = NostrSeedPhrase.nsecToSeed(testNsec);
      expect(result.seedPhrase).toBeTruthy();
      expect(typeof result.seedPhrase).toBe('string');
    });

    it('should throw error for invalid nsec', () => {
      expect(() => NostrSeedPhrase.nsecToSeed('invalid-nsec')).toThrow();
    });
  });

  describe('seedToNsec', () => {
    it('should convert mnemonic to nsec', () => {
      const result = NostrSeedPhrase.seedToNsec(testMnemonic);
      expect(result.nsec).toBeTruthy();
      expect(result.npub).toBeTruthy();
      expect(result.privateKeyHex).toBeTruthy();
      expect(result.publicKeyHex).toBeTruthy();
      expect(result.nsec.startsWith('nsec')).toBe(true);
      expect(result.npub.startsWith('npub')).toBe(true);
      expect(/^[0-9a-f]{64}$/.test(result.privateKeyHex)).toBe(true);
      expect(/^[0-9a-f]{64}$/.test(result.publicKeyHex)).toBe(true);
    });

    it('should throw error for invalid mnemonic', () => {
      expect(() => NostrSeedPhrase.seedToNsec('invalid mnemonic')).toThrow();
    });
  });

  describe('validateSeedPhrase', () => {
    it('should validate correct mnemonic', () => {
      expect(NostrSeedPhrase.validateSeedPhrase(testMnemonic)).toBe(true);
    });

    it('should reject invalid mnemonic', () => {
      expect(NostrSeedPhrase.validateSeedPhrase('invalid mnemonic')).toBe(false);
    });
  });

  describe('generateNew', () => {
    it('should generate new key pair', () => {
      const result = NostrSeedPhrase.generateNew();
      expect(result.nsec).toBeTruthy();
      expect(result.npub).toBeTruthy();
      expect(result.seedPhrase).toBeTruthy();
      expect(result.privateKeyHex).toBeTruthy();
      expect(result.publicKeyHex).toBeTruthy();
    });

    it('should generate valid seed phrase', () => {
      const result = NostrSeedPhrase.generateNew();
      expect(NostrSeedPhrase.validateSeedPhrase(result.seedPhrase)).toBe(true);
    });

    it('should generate convertible keys', () => {
      const result = NostrSeedPhrase.generateNew();
      const convertedSeed = NostrSeedPhrase.nsecToSeed(result.nsec);
      expect(convertedSeed.seedPhrase).toBeTruthy();
    });
  });

  describe('hex conversion', () => {
    it('should create key pair from hex', () => {
      const initial = NostrSeedPhrase.generateNew();
      const fromHex = NostrSeedPhrase.fromHex(initial.privateKeyHex);
      expect(fromHex.nsec).toBe(initial.nsec);
      expect(fromHex.npub).toBe(initial.npub);
      expect(fromHex.privateKeyHex).toBe(initial.privateKeyHex);
      expect(fromHex.publicKeyHex).toBe(initial.publicKeyHex);
    });

    it('should convert nsec to hex', () => {
      const initial = NostrSeedPhrase.generateNew();
      const hex = NostrSeedPhrase.nsecToHex(initial.nsec);
      expect(hex).toBe(initial.privateKeyHex);
      expect(/^[0-9a-f]{64}$/.test(hex)).toBe(true);
    });

    it('should convert npub to hex', () => {
      const initial = NostrSeedPhrase.generateNew();
      const hex = NostrSeedPhrase.npubToHex(initial.npub);
      expect(hex).toBe(initial.publicKeyHex);
      expect(/^[0-9a-f]{64}$/.test(hex)).toBe(true);
    });

    it('should convert hex to npub', () => {
      const initial = NostrSeedPhrase.generateNew();
      const npub = NostrSeedPhrase.hexToNpub(initial.publicKeyHex);
      expect(npub).toBe(initial.npub);
      expect(npub.startsWith('npub')).toBe(true);
    });

    it('should convert hex to nsec', () => {
      const initial = NostrSeedPhrase.generateNew();
      const nsec = NostrSeedPhrase.hexToNsec(initial.privateKeyHex);
      expect(nsec).toBe(initial.nsec);
      expect(nsec.startsWith('nsec')).toBe(true);
    });

    it('should throw error for invalid hex private key', () => {
      expect(() => NostrSeedPhrase.fromHex('invalid')).toThrow();
      expect(() => NostrSeedPhrase.hexToNsec('invalid')).toThrow();
    });

    it('should throw error for invalid hex public key', () => {
      expect(() => NostrSeedPhrase.hexToNpub('invalid')).toThrow();
    });
  });

  describe('roundtrip conversion', () => {
    it('should maintain key integrity through conversions', () => {
      const initial = NostrSeedPhrase.generateNew();
      const seed = NostrSeedPhrase.nsecToSeed(initial.nsec);
      const final = NostrSeedPhrase.seedToNsec(seed.seedPhrase);
      expect(final.nsec).toBe(initial.nsec);
      expect(final.npub).toBe(initial.npub);
      expect(final.privateKeyHex).toBe(initial.privateKeyHex);
      expect(final.publicKeyHex).toBe(initial.publicKeyHex);
    });

    it('should maintain consistent npub across conversions', () => {
      // Start with a generated key pair
      const initial = NostrSeedPhrase.generateNew();
      
      // Convert to seed phrase and back
      const seed = NostrSeedPhrase.nsecToSeed(initial.nsec);
      const fromSeed = NostrSeedPhrase.seedToNsec(seed.seedPhrase);
      
      // Verify both nsec and npub remain consistent
      expect(fromSeed.nsec).toBe(initial.nsec);
      expect(fromSeed.npub).toBe(initial.npub);
      expect(fromSeed.npub.startsWith('npub')).toBe(true);
    });

    it('should maintain consistency across all formats', () => {
      // Start with a generated key pair
      const initial = NostrSeedPhrase.generateNew();
      
      // Convert through various formats
      const hex = NostrSeedPhrase.nsecToHex(initial.nsec);
      const fromHex = NostrSeedPhrase.fromHex(hex);
      const npubFromHex = NostrSeedPhrase.hexToNpub(fromHex.publicKeyHex);
      const nsecFromHex = NostrSeedPhrase.hexToNsec(fromHex.privateKeyHex);
      
      // Verify everything matches
      expect(fromHex.nsec).toBe(initial.nsec);
      expect(fromHex.npub).toBe(initial.npub);
      expect(npubFromHex).toBe(initial.npub);
      expect(nsecFromHex).toBe(initial.nsec);
      expect(fromHex.privateKeyHex).toBe(initial.privateKeyHex);
      expect(fromHex.publicKeyHex).toBe(initial.publicKeyHex);
    });
  });
});
