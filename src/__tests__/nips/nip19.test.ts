import { describe, it, expect } from 'vitest';
import { mockSecp256k1, mockBech32, TEST_CONSTANTS } from '../test-utils';
import {
  npubEncode,
  nsecEncode,
  noteEncode,
  npubDecode,
  nsecDecode,
  noteDecode,
  decodeNip19,
  hexToNpub,
  hexToNsec
} from '../../nips/nip19';

// Setup mocks
mockSecp256k1();
mockBech32();

describe('NIP-19: bech32-encoded entities', () => {
  describe('Encoding', () => {
    it('should encode public keys to npub format', () => {
      const npub = npubEncode(TEST_CONSTANTS.PUBLIC_KEY);
      expect(npub).toBeDefined();
      expect(npub.startsWith('npub1')).toBe(true);
    });

    it('should encode private keys to nsec format', () => {
      const nsec = nsecEncode(TEST_CONSTANTS.PRIVATE_KEY);
      expect(nsec).toBeDefined();
      expect(nsec.startsWith('nsec1')).toBe(true);
    });

    it('should encode note IDs', () => {
      const noteId = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const note = noteEncode(noteId);
      expect(note).toBeDefined();
      expect(note.startsWith('note1')).toBe(true);
    });
  });

  describe('Decoding', () => {
    it('should decode npub format to public keys', () => {
      const npub = npubEncode(TEST_CONSTANTS.PUBLIC_KEY);
      const decoded = npubDecode(npub);
      expect(decoded).toBe(TEST_CONSTANTS.PUBLIC_KEY);
    });

    it('should decode nsec format to private keys', () => {
      const nsec = nsecEncode(TEST_CONSTANTS.PRIVATE_KEY);
      const decoded = nsecDecode(nsec);
      expect(decoded).toBe(TEST_CONSTANTS.PRIVATE_KEY);
    });

    it('should decode note format to note IDs', () => {
      const noteId = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const note = noteEncode(noteId);
      const decoded = noteDecode(note);
      expect(decoded).toBe(noteId);
    });

    it('should handle generic decoding', () => {
      const testCases = [
        { input: npubEncode(TEST_CONSTANTS.PUBLIC_KEY), type: 'npub' },
        { input: nsecEncode(TEST_CONSTANTS.PRIVATE_KEY), type: 'nsec' },
        { input: noteEncode('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'), type: 'note' }
      ];

      testCases.forEach(({ input, type }) => {
        const decoded = decodeNip19(input);
        expect(decoded.type).toBe(type);
        expect(decoded.data).toBeDefined();
      });
    });
  });

  describe('Hex Conversion', () => {
    it('should convert hex to npub', () => {
      const npub = hexToNpub(TEST_CONSTANTS.PUBLIC_KEY);
      expect(npub).toBeDefined();
      expect(npub.startsWith('npub1')).toBe(true);
    });

    it('should convert hex to nsec', () => {
      const nsec = hexToNsec(TEST_CONSTANTS.PRIVATE_KEY);
      expect(nsec).toBeDefined();
      expect(nsec.startsWith('nsec1')).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid npub format', () => {
      expect(() => npubDecode('invalid')).toThrow();
      expect(() => npubDecode('npub1invalid')).toThrow();
    });

    it('should handle invalid nsec format', () => {
      expect(() => nsecDecode('invalid')).toThrow();
      expect(() => nsecDecode('nsec1invalid')).toThrow();
    });

    it('should handle invalid note format', () => {
      expect(() => noteDecode('invalid')).toThrow();
      expect(() => noteDecode('note1invalid')).toThrow();
    });
  });
});
