import { describe, it, expect } from 'vitest';
import {
  createDelegation,
  verifyDelegation,
  createDelegationTag,
  Nip26Error
} from '../../nips/nip26';
import { generatePrivateKey, getPublicKey } from '../../crypto/keys';

describe('NIP-26: Delegated Event Signing', () => {
  const delegatorPrivateKey = generatePrivateKey();
  const delegatorPublicKey = getPublicKey(delegatorPrivateKey);
  const delegateePrivateKey = generatePrivateKey();
  const delegateePublicKey = getPublicKey(delegateePrivateKey);
  const conditions = "kinds=1,2&created_at<1679000000";
  const since = Math.floor(Date.now() / 1000);
  const until = since + 60 * 60 * 24; // 24 hours from now

  describe('Delegation Creation', () => {
    it('should create valid delegation tokens', async () => {
      const token = await createDelegation(
        delegatorPrivateKey,
        delegateePublicKey,
        conditions,
        since,
        until
      );
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.length).toBe(128); // 64 bytes in hex
    });

    it('should reject invalid private keys', async () => {
      await expect(createDelegation(
        'invalid_key',
        delegateePublicKey,
        conditions,
        since,
        until
      )).rejects.toThrow(Nip26Error);
    });

    it('should reject invalid public keys', async () => {
      await expect(createDelegation(
        delegatorPrivateKey,
        'invalid_key',
        conditions,
        since,
        until
      )).rejects.toThrow(Nip26Error);
    });
  });

  describe('Delegation Verification', () => {
    it('should verify valid delegations', async () => {
      const token = await createDelegation(
        delegatorPrivateKey,
        delegateePublicKey,
        conditions,
        since,
        until
      );
      const isValid = await verifyDelegation(
        delegatorPublicKey,
        delegateePublicKey,
        conditions,
        since,
        until,
        token
      );
      expect(isValid).toBe(true);
    });

    it('should reject invalid delegations', async () => {
      const token = await createDelegation(
        delegatorPrivateKey,
        delegateePublicKey,
        conditions,
        since,
        until
      );
      const isValid = await verifyDelegation(
        delegateePublicKey, // wrong key order
        delegatorPublicKey,
        conditions,
        since,
        until,
        token
      );
      expect(isValid).toBe(false);
    });
  });

  describe('Delegation Tags', () => {
    it('should create valid delegation tags', async () => {
      const tag = await createDelegationTag(
        delegatorPrivateKey,
        delegateePublicKey,
        conditions,
        since,
        until
      );
      expect(Array.isArray(tag)).toBe(true);
      expect(tag.length).toBe(6);
      expect(tag[0]).toBe('delegation');
      expect(tag[1]).toBe(delegatorPublicKey);
      expect(tag[2]).toBe(conditions);
      expect(tag[3]).toBe(since.toString());
      expect(tag[4]).toBe(until.toString());
      expect(typeof tag[5]).toBe('string');
    });
  });
});
