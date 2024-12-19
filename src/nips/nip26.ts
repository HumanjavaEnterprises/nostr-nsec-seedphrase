import { schnorrSign, schnorrVerify } from '../crypto/signing';
import { getPublicKey } from '../crypto/keys';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export class Nip26Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Nip26Error';
  }
}

/**
 * Conditions for delegation according to NIP-26
 */
export interface DelegationConditions {
  kinds?: number[];
  since?: number;
  until?: number;
}

/**
 * Create a delegation token according to NIP-26
 * @param delegatorPrivateKey - The private key of the delegator
 * @param delegateePubkey - The public key of the person receiving the delegation
 * @param conditions - Conditions for the delegation (kinds, since, until)
 * @returns The delegation token
 */
export async function createDelegation(
  delegatorPrivateKey: string,
  delegateePubkey: string,
  conditions: DelegationConditions
): Promise<string> {
  try {
    const query = [
      'delegation',
      delegateePubkey,
      conditions.kinds?.join(',') || '',
      conditions.since?.toString() || '',
      conditions.until?.toString() || '',
    ].join(':');

    const messageBytes = new TextEncoder().encode(query);
    const hash = sha256(messageBytes);
    const signature = await schnorrSign(bytesToHex(hash), delegatorPrivateKey);
    
    return signature;
  } catch (error) {
    throw new Nip26Error(`Failed to create delegation: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Verify a delegation token
 * @param token - The delegation token to verify
 * @param delegatorPubkey - The public key of the delegator
 * @param delegateePubkey - The public key of the delegatee
 * @param conditions - The conditions under which the delegation was created
 * @returns boolean indicating if the delegation is valid
 */
export async function verifyDelegation(
  token: string,
  delegatorPubkey: string,
  delegateePubkey: string,
  conditions: DelegationConditions
): Promise<boolean> {
  try {
    const query = [
      'delegation',
      delegateePubkey,
      conditions.kinds?.join(',') || '',
      conditions.since?.toString() || '',
      conditions.until?.toString() || '',
    ].join(':');

    const messageBytes = new TextEncoder().encode(query);
    const hash = sha256(messageBytes);
    
    return await schnorrVerify(token, bytesToHex(hash), delegatorPubkey);
  } catch {
    return false;
  }
}

/**
 * Check if a delegation is currently valid based on time conditions
 * @param conditions - The delegation conditions to check
 * @returns boolean indicating if the delegation is currently valid
 */
export function isDelegationValid(conditions: DelegationConditions): boolean {
  const now = Math.floor(Date.now() / 1000);
  
  if (conditions.since && now < conditions.since) {
    return false;
  }
  
  if (conditions.until && now > conditions.until) {
    return false;
  }
  
  return true;
}

/**
 * Create a delegation tag for use in NOSTR events
 * @param delegator - The public key of the delegator
 * @param conditions - The delegation conditions
 * @param token - The delegation token
 * @returns Array representing the delegation tag
 */
export function createDelegationTag(
  delegator: string,
  conditions: DelegationConditions,
  token: string
): string[] {
  return [
    'delegation',
    delegator,
    conditions.kinds?.join(',') || '',
    conditions.since?.toString() || '',
    conditions.until?.toString() || '',
    token,
  ];
}
