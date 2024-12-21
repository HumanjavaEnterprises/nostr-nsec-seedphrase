import { describe, it, expect, beforeAll } from 'vitest';
import { TEST_CONSTANTS, setupHMAC } from '../test-utils';
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
import { PREFIXES } from '../../crypto/encoding';

describe('NIP-19: bech32-encoded entities', () => {
  beforeAll(() => {
    setupHMAC();
  });

  describe('Encoding', () => {
    it('should encode public keys to npub format', () => {
      const npub = npubEncode(TEST_CONSTANTS.PUBLIC_KEY);
      expect(npub).toMatch(/^npub1/);
    });

    it('should encode private keys to nsec format', () => {
      const nsec = nsecEncode(TEST_CONSTANTS.PRIVATE_KEY);
      expect(nsec).toMatch(/^nsec1/);
    });

    it('should encode note IDs', () => {
      const noteId = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const note = noteEncode(noteId);
      expect(note).toMatch(/^note1/);
    });
  });

  describe('Decoding', () => {
    it('should decode npub format to public keys', () => {
      const pubkey = TEST_CONSTANTS.PUBLIC_KEY;
      const npub = npubEncode(pubkey);
      expect(npub).toMatch(/^npub1/);
      const decoded = npubDecode(npub);
      expect(decoded.toLowerCase()).toBe(pubkey.toLowerCase());
    });

    it('should decode nsec format to private keys', () => {
      const privkey = TEST_CONSTANTS.PRIVATE_KEY;
      const nsec = nsecEncode(privkey);
      expect(nsec).toMatch(/^nsec1/);
      const decoded = nsecDecode(nsec);
      expect(decoded.toLowerCase()).toBe(privkey.toLowerCase());
    });

    it('should decode note format to note IDs', () => {
      const noteId = TEST_CONSTANTS.TEST_EVENT.id;
      const note = noteEncode(noteId);
      expect(note).toMatch(/^note1/);
      const decoded = noteDecode(note);
      expect(decoded.toLowerCase()).toBe(noteId.toLowerCase());
    });

    it('should handle generic decoding', () => {
      // Test npub decoding
      const npub = npubEncode(TEST_CONSTANTS.PUBLIC_KEY);
      const decodedNpub = decodeNip19(npub);
      expect(decodedNpub.type).toBe(PREFIXES.NPUB);
      if (decodedNpub.type === PREFIXES.NPUB) {
        expect((decodedNpub.data as string).toLowerCase()).toBe(TEST_CONSTANTS.PUBLIC_KEY.toLowerCase());
      }

      // Test nsec decoding
      const nsec = nsecEncode(TEST_CONSTANTS.PRIVATE_KEY);
      const decodedNsec = decodeNip19(nsec);
      expect(decodedNsec.type).toBe(PREFIXES.NSEC);
      if (decodedNsec.type === PREFIXES.NSEC) {
        expect((decodedNsec.data as string).toLowerCase()).toBe(TEST_CONSTANTS.PRIVATE_KEY.toLowerCase());
      }
    });
  });

  describe('Hex Conversion', () => {
    it('should convert hex to npub', () => {
      const npub = hexToNpub(TEST_CONSTANTS.PUBLIC_KEY);
      expect(npub).toMatch(/^npub1/);
    });

    it('should convert hex to nsec', () => {
      const nsec = hexToNsec(TEST_CONSTANTS.PRIVATE_KEY);
      expect(nsec).toMatch(/^nsec1/);
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
