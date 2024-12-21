import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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
    
    beforeEach(() => {
      vi.stubGlobal('fetch', mockFetch);
      mockFetch.mockReset();
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it('should verify valid NIP-05 identifier', async () => {
      const pubkey = '2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5c12';
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          names: {
            alice: pubkey
          }
        })
      });

      const result = await verifyNip05('alice@example.com', pubkey);
      expect(result).toBe(true);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/.well-known/nostr.json?name=alice'
      );
    });

    it('should return false for invalid NIP-05 identifier', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false
      });

      const result = await verifyNip05('invalid@example.com', '2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5c12');
      expect(result).toBe(false);
    });
  });

  describe('getNip05Relays', () => {
    const mockFetch = vi.fn();
    
    beforeEach(() => {
      vi.stubGlobal('fetch', mockFetch);
      mockFetch.mockReset();
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it('should get relays for valid NIP-05 identifier', async () => {
      const pubkey = '2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5c12';
      const relays = ['wss://relay1.example.com', 'wss://relay2.example.com'];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          names: {
            alice: pubkey
          },
          relays: {
            [pubkey]: relays
          }
        })
      });

      const result = await getNip05Relays('alice@example.com');
      expect(result).toEqual(relays);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/.well-known/nostr.json?name=alice'
      );
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
