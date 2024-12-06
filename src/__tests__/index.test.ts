import { 
  generateKeyPairWithSeed,
  fromHex,
  nsecToHex,
  npubToHex,
  hexToNpub,
  hexToNsec,
  validateSeedPhrase,
  seedPhraseToKeyPair,
  generateSeedPhrase
} from '../index';

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

describe('Nostr Seed Phrase Library', () => {
  // Generate a valid key pair for testing
  const initial = generateKeyPairWithSeed();
  
  describe('seed phrase operations', () => {
    it('should generate valid seed phrase', () => {
      const seedPhrase = generateSeedPhrase();
      expect(validateSeedPhrase(seedPhrase)).toBe(true);
    });

    it('should convert seed phrase to key pair', () => {
      const seedPhrase = generateSeedPhrase();
      const keyPair = seedPhraseToKeyPair(seedPhrase);
      expect(keyPair.privateKey).toBeTruthy();
      expect(keyPair.publicKey).toBeTruthy();
      expect(keyPair.nsec).toBeTruthy();
      expect(keyPair.npub).toBeTruthy();
    });

    it('should reject invalid seed phrase', () => {
      expect(validateSeedPhrase('invalid mnemonic')).toBe(false);
    });

    it('should throw error when converting invalid seed phrase to key pair', () => {
      expect(() => seedPhraseToKeyPair('invalid mnemonic')).toThrow();
    });
  });

  describe('key pair generation', () => {
    it('should generate new key pair', () => {
      const result = generateKeyPairWithSeed();
      expect(result.nsec).toBeTruthy();
      expect(result.npub).toBeTruthy();
      expect(result.seedPhrase).toBeTruthy();
      expect(result.privateKey).toBeTruthy();
      expect(result.publicKey).toBeTruthy();
    });

    it('should generate valid seed phrase', () => {
      const result = generateKeyPairWithSeed();
      expect(validateSeedPhrase(result.seedPhrase)).toBe(true);
    });

    it('should handle errors in key pair generation', () => {
      // Mock crypto.getRandomValues to throw
      const originalGetRandomValues = crypto.getRandomValues;
      crypto.getRandomValues = () => { throw new Error('Random generation failed'); };
      
      expect(() => generateKeyPairWithSeed()).toThrow('Failed to generate new key pair');
      
      // Restore original function
      crypto.getRandomValues = originalGetRandomValues;
    });
  });

  describe('hex conversion', () => {
    it('should create key pair from hex', () => {
      const initial = generateKeyPairWithSeed();
      const fromHexResult = fromHex(initial.privateKey);
      expect(fromHexResult.nsec).toBe(initial.nsec);
      expect(fromHexResult.npub).toBe(initial.npub);
      expect(fromHexResult.privateKey).toBe(initial.privateKey);
      expect(fromHexResult.publicKey).toBe(initial.publicKey);
    });

    it('should convert nsec to hex', () => {
      const initial = generateKeyPairWithSeed();
      const hex = nsecToHex(initial.nsec);
      expect(hex).toBe(initial.privateKey);
      expect(/^[0-9a-fA-F]{64}$/.test(hex)).toBe(true);
    });

    it('should convert npub to hex', () => {
      const initial = generateKeyPairWithSeed();
      const hex = npubToHex(initial.npub);
      expect(hex).toBe(initial.publicKey);
      expect(/^[0-9a-fA-F]{64}$/.test(hex)).toBe(true);
    });

    it('should convert hex to npub', () => {
      const initial = generateKeyPairWithSeed();
      const npub = hexToNpub(initial.publicKey);
      expect(npub).toBe(initial.npub);
      expect(npub.startsWith('npub')).toBe(true);
    });

    it('should convert hex to nsec', () => {
      const initial = generateKeyPairWithSeed();
      const nsec = hexToNsec(initial.privateKey);
      expect(nsec).toBe(initial.nsec);
      expect(nsec.startsWith('nsec')).toBe(true);
    });

    it('should throw error for invalid hex', () => {
      expect(() => fromHex('invalid-hex')).toThrow();
      expect(() => hexToNpub('invalid-hex')).toThrow();
      expect(() => hexToNsec('invalid-hex')).toThrow();
    });

    it('should throw error for invalid nsec format', () => {
      expect(() => nsecToHex('invalid-nsec')).toThrow('Failed to convert nsec to hex');
      expect(() => nsecToHex('npub1xxxxxx')).toThrow('Failed to convert nsec to hex');
    });

    it('should throw error for invalid npub format', () => {
      expect(() => npubToHex('invalid-npub')).toThrow('Failed to convert npub to hex');
      expect(() => npubToHex('nsec1xxxxxx')).toThrow('Failed to convert npub to hex');
    });

    it('should throw error for hex with wrong length', () => {
      expect(() => fromHex('1234')).toThrow('Invalid hex private key format');
      expect(() => fromHex('g'.repeat(64))).toThrow('Invalid hex private key format');
    });
  });
});
