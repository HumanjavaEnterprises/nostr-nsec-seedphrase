import { describe, it, expect, beforeEach } from 'vitest';
import { generatePrivateKey, getPublicKey } from '../../crypto/keys';
import {
  createDelegation,
  verifyDelegation,
  isDelegationValid,
  createDelegationTag,
  DelegationConditions
} from '../../nips/nip26';

describe('NIP-26: Delegated Event Signing', () => {
  let delegatorPrivateKey: string;
  let delegatorPublicKey: string;
  let delegateePrivateKey: string;
  let delegateePublicKey: string;
  
  beforeEach(() => {
    // Generate fresh keys for each test
    delegatorPrivateKey = generatePrivateKey();
    delegatorPublicKey = getPublicKey(delegatorPrivateKey);
    delegateePrivateKey = generatePrivateKey();
    delegateePublicKey = getPublicKey(delegateePrivateKey);
  });

  describe('createDelegation', () => {
    it('should create a valid delegation token', async () => {
      const conditions: DelegationConditions = {
        kinds: [1, 2],
        since: Math.floor(Date.now() / 1000),
        until: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
      };

      const token = await createDelegation(delegatorPrivateKey, delegateePublicKey, conditions);
      expect(token).toBeTruthy();
      expect(typeof token).toBe('string');
    });

    it('should throw error for invalid keys', async () => {
      const conditions: DelegationConditions = {
        kinds: [1],
        since: Math.floor(Date.now() / 1000),
        until: Math.floor(Date.now() / 1000) + 3600
      };

      await expect(() =>
        createDelegation('invalid-key', delegateePublicKey, conditions)
      ).rejects.toThrow();

      await expect(() =>
        createDelegation(delegatorPrivateKey, 'invalid-key', conditions)
      ).rejects.toThrow();
    });
  });

  describe('verifyDelegation', () => {
    it('should verify valid delegation', async () => {
      const conditions: DelegationConditions = {
        kinds: [1],
        since: Math.floor(Date.now() / 1000),
        until: Math.floor(Date.now() / 1000) + 3600
      };

      const token = await createDelegation(delegatorPrivateKey, delegateePublicKey, conditions);
      const isValid = await verifyDelegation(token, delegatorPublicKey, delegateePublicKey, conditions);
      expect(isValid).toBe(true);
    });

    it('should reject invalid delegation', async () => {
      const conditions: DelegationConditions = {
        kinds: [1],
        since: Math.floor(Date.now() / 1000),
        until: Math.floor(Date.now() / 1000) + 3600
      };

      const token = await createDelegation(delegatorPrivateKey, delegateePublicKey, conditions);
      const isValid = await verifyDelegation(token, delegateePublicKey, delegatorPublicKey, conditions);
      expect(isValid).toBe(false);
    });
  });

  describe('isDelegationValid', () => {
    it('should validate time-based conditions', () => {
      const now = Math.floor(Date.now() / 1000);
      
      // Valid time window
      expect(isDelegationValid({
        since: now - 3600,
        until: now + 3600
      })).toBe(true);

      // Expired delegation
      expect(isDelegationValid({
        since: now - 7200,
        until: now - 3600
      })).toBe(false);

      // Future delegation
      expect(isDelegationValid({
        since: now + 3600,
        until: now + 7200
      })).toBe(false);
    });
  });

  describe('createDelegationTag', () => {
    it('should create valid delegation tag', async () => {
      const conditions: DelegationConditions = {
        kinds: [1],
        since: Math.floor(Date.now() / 1000),
        until: Math.floor(Date.now() / 1000) + 3600
      };

      const token = await createDelegation(delegatorPrivateKey, delegateePublicKey, conditions);
      const tag = await createDelegationTag(
        delegatorPublicKey,
        conditions,
        token
      );

      expect(Array.isArray(tag)).toBe(true);
      expect(tag[0]).toBe('delegation');
      expect(tag[1]).toBe(delegatorPublicKey);
      expect(typeof tag[2]).toBe('string');
    });
  });
});
