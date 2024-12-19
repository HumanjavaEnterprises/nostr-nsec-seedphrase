import { describe, it, expect } from 'vitest';
import { mockSecp256k1, mockBech32, TEST_CONSTANTS } from '../test-utils';
import {
  countLeadingZeroes,
  hasValidProofOfWork,
  generateProofOfWork
} from '../../nips/nip13';

// Setup mocks
mockSecp256k1();
mockBech32();

describe('NIP-13: Proof of Work', () => {
  describe('Leading Zeroes Counting', () => {
    it('should count leading zeroes correctly', () => {
      const testCases = [
        { hex: '0000ff', expected: 16 },
        { hex: '00ff00', expected: 8 },
        { hex: 'ff0000', expected: 0 },
        { hex: '000000', expected: 24 },
      ];

      testCases.forEach(({ hex, expected }) => {
        const count = countLeadingZeroes(hex);
        expect(count).toBe(expected);
      });
    });
  });

  describe('Proof of Work Validation', () => {
    it('should validate proof of work correctly', async () => {
      const baseEvent = {
        pubkey: TEST_CONSTANTS.PUBLIC_KEY,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello, Nostr!'
      };

      // Generate events with different difficulties
      const event16 = await generateProofOfWork(baseEvent, 16);
      const event8 = await generateProofOfWork(baseEvent, 8);

      // Test with different difficulty targets
      expect(hasValidProofOfWork(event16, 16)).toBe(true);
      expect(hasValidProofOfWork(event16, 24)).toBe(false);
      expect(hasValidProofOfWork(event8, 8)).toBe(true);
      expect(hasValidProofOfWork(event8, 16)).toBe(false);
    });
  });

  describe('Proof of Work Generation', () => {
    it('should generate valid proof of work', async () => {
      const event = {
        pubkey: TEST_CONSTANTS.PUBLIC_KEY,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello, Nostr!'
      };

      const difficulty = 8; // Use a low difficulty for testing
      const eventWithPow = await generateProofOfWork(event, difficulty);

      expect(eventWithPow).toBeDefined();
      expect(eventWithPow.id).toBeDefined();
      expect(hasValidProofOfWork(eventWithPow, difficulty)).toBe(true);
    });

    it('should respect minimum difficulty', async () => {
      const event = {
        pubkey: TEST_CONSTANTS.PUBLIC_KEY,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello, Nostr!'
      };

      const difficulty = 0;
      const eventWithPow = await generateProofOfWork(event, difficulty);

      expect(eventWithPow).toBeDefined();
      expect(eventWithPow.id).toBeDefined();
      expect(hasValidProofOfWork(eventWithPow, difficulty)).toBe(true);
    });

    it('should throw error for invalid difficulty', async () => {
      const event = {
        pubkey: TEST_CONSTANTS.PUBLIC_KEY,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello, Nostr!'
      };

      await expect(generateProofOfWork(event, -1)).rejects.toThrow('Difficulty must be non-negative');
    });
  });
});
