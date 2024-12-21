import { describe, it, expect, beforeAll } from 'vitest';
import { TEST_CONSTANTS, setupHMAC } from '../test-utils';
import { countLeadingZeroes, hasValidProofOfWork, generateProofOfWork } from '../../nips/nip13';
import { UnsignedEvent } from '../../types/events';

describe('NIP-13: Proof of Work', () => {
  beforeAll(() => {
    setupHMAC();
  });

  describe('Leading Zeroes Counting', () => {
    it('should correctly count leading zeroes', () => {
      const testCases = [
        { hex: '00ff', expected: 8 },
        { hex: '0fff', expected: 4 },
        { hex: 'ffff', expected: 0 }
      ];

      testCases.forEach(({ hex, expected }) => {
        const count = countLeadingZeroes(hex);
        expect(count).toBe(expected);
      });
    });
  });

  describe('Proof of Work Validation', () => {
    it('should validate proof of work', () => {
      const baseEvent = {
        id: '00ff',
        pubkey: TEST_CONSTANTS.PUBLIC_KEY,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello, Nostr!',
        nonce: '0'
      };

      expect(hasValidProofOfWork(baseEvent, 0)).toBe(true);
    });
  });

  describe('Proof of Work Generation', () => {
    it('should generate valid proof of work', async () => {
      const event: UnsignedEvent = {
        pubkey: TEST_CONSTANTS.PUBLIC_KEY,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello, Nostr!'
      };

      const difficulty = 0;
      const eventWithPow = await generateProofOfWork(event, difficulty);
      
      expect(eventWithPow).toBeDefined();
      expect(eventWithPow.nonce).toBeDefined();
      expect(hasValidProofOfWork(eventWithPow, difficulty)).toBe(true);
    });

    it('should throw error for invalid difficulty', () => {
      const event: UnsignedEvent = {
        pubkey: TEST_CONSTANTS.PUBLIC_KEY,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello, Nostr!'
      };

      expect(() => generateProofOfWork(event, -1)).rejects.toThrow();
    });
  });
});
