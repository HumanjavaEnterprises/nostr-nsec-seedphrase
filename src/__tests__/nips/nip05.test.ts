import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  verifyNip05,
  getNip05Relays,
  formatNip05,
  parseNip05
} from '../../nips/nip05';

describe('NIP-05: DNS-based Names', () => {
  describe('formatNip05', () => {
    it('should format name and domain correctly', () => {
      expect(formatNip05('alice', 'example.com')).toBe('alice@example.com');
    });
  });

  describe('parseNip05', () => {
    it('should parse valid NIP-05 identifier', () => {
      const result = parseNip05('alice@example.com');
      expect(result).toEqual({
        name: 'alice',
        domain: 'example.com'
      });
    });

    it('should return null for invalid identifier', () => {
      expect(parseNip05('invalid-identifier')).toBeNull();
    });
  });

  describe('verifyNip05', () => {
    const mockFetch = vi.fn();
    global.fetch = mockFetch;

    beforeEach(() => {
      mockFetch.mockReset();
    });

    it('should verify valid NIP-05 identifier', async () => {
      const pubkey = '0123456789abcdef';
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          names: {
            alice: pubkey
          }
        })
      });

      const result = await verifyNip05('alice@example.com', pubkey);
      expect(result).toBe(true);
    });

    it('should return false for invalid NIP-05 identifier', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false
      });

      const result = await verifyNip05('invalid@example.com', '0123456789abcdef');
      expect(result).toBe(false);
    });
  });

  describe('getNip05Relays', () => {
    const mockFetch = vi.fn();
    global.fetch = mockFetch;

    beforeEach(() => {
      mockFetch.mockReset();
    });

    it('should get relays for valid NIP-05 identifier', async () => {
      const relays = ['wss://relay1.example.com', 'wss://relay2.example.com'];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          relays: relays
        })
      });

      const result = await getNip05Relays('alice@example.com');
      expect(result).toEqual(relays);
    });

    it('should return null for invalid NIP-05 identifier', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false
      });

      const result = await getNip05Relays('invalid@example.com');
      expect(result).toBeNull();
    });
  });
});
