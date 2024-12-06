import { 
  generateNew,
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
  const initial = generateNew();
  const testNsec = initial.nsec;
  const testSeed = generateSeedPhrase();
  
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
  });

  describe('key pair generation', () => {
    it('should generate new key pair', () => {
      const result = generateNew();
      expect(result.nsec).toBeTruthy();
      expect(result.npub).toBeTruthy();
      expect(result.seedPhrase).toBeTruthy();
      expect(result.privateKey).toBeTruthy();
      expect(result.publicKey).toBeTruthy();
    });

    it('should generate valid seed phrase', () => {
      const result = generateNew();
      expect(validateSeedPhrase(result.seedPhrase)).toBe(true);
    });
  });

  describe('hex conversion', () => {
    it('should create key pair from hex', () => {
      const initial = generateNew();
      const fromHexResult = fromHex(initial.privateKey);
      expect(fromHexResult.nsec).toBe(initial.nsec);
      expect(fromHexResult.npub).toBe(initial.npub);
      expect(fromHexResult.privateKey).toBe(initial.privateKey);
      expect(fromHexResult.publicKey).toBe(initial.publicKey);
    });

    it('should convert nsec to hex', () => {
      const initial = generateNew();
      const hex = nsecToHex(initial.nsec);
      expect(hex).toBe(initial.privateKey);
      expect(/^[0-9a-fA-F]{64}$/.test(hex)).toBe(true);
    });

    it('should convert npub to hex', () => {
      const initial = generateNew();
      const hex = npubToHex(initial.npub);
      expect(hex).toBe(initial.publicKey);
      expect(/^[0-9a-fA-F]{64}$/.test(hex)).toBe(true);
    });

    it('should convert hex to npub', () => {
      const initial = generateNew();
      const npub = hexToNpub(initial.publicKey);
      expect(npub).toBe(initial.npub);
      expect(npub.startsWith('npub')).toBe(true);
    });

    it('should convert hex to nsec', () => {
      const initial = generateNew();
      const nsec = hexToNsec(initial.privateKey);
      expect(nsec).toBe(initial.nsec);
      expect(nsec.startsWith('nsec')).toBe(true);
    });

    it('should throw error for invalid hex', () => {
      expect(() => fromHex('invalid-hex')).toThrow();
      expect(() => hexToNpub('invalid-hex')).toThrow();
      expect(() => hexToNsec('invalid-hex')).toThrow();
    });
  });
});
