import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { schnorrSign, schnorrVerify } from "../crypto/signing";
import { validatePrivateKey, validatePublicKey, getPublicKey } from "../crypto/keys";

export class Nip26Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Nip26Error';
  }
}

/**
 * Create a delegation token for delegated event signing
 */
export async function createDelegation(
  delegatorPrivateKey: string,
  delegateePubkey: string,
  conditions: string = "",
  since: number = 0,
  until: number = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 // 30 days by default
): Promise<string> {
  try {
    if (!validatePrivateKey(delegatorPrivateKey)) {
      throw new Error('Invalid delegator private key');
    }
    if (!validatePublicKey(delegateePubkey)) {
      throw new Error('Invalid delegatee public key');
    }

    const delegatorPubkey = getPublicKey(delegatorPrivateKey);
    
    const token = [
      "delegation",
      delegatorPubkey,
      delegateePubkey,
      conditions,
      since.toString(),
      until.toString(),
    ].join(":");

    const hash = sha256(Buffer.from(token));
    return await schnorrSign(bytesToHex(hash), delegatorPrivateKey);
  } catch (error) {
    throw new Nip26Error(`Failed to create delegation: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Verify a delegation token
 */
export async function verifyDelegation(
  delegatorPubkey: string,
  delegateePubkey: string,
  conditions: string,
  since: number,
  until: number,
  token: string
): Promise<boolean> {
  try {
    if (!validatePublicKey(delegatorPubkey)) {
      throw new Error('Invalid delegator public key');
    }
    if (!validatePublicKey(delegateePubkey)) {
      throw new Error('Invalid delegatee public key');
    }

    const message = [
      "delegation",
      delegatorPubkey,
      delegateePubkey,
      conditions,
      since.toString(),
      until.toString(),
    ].join(":");

    const hash = sha256(Buffer.from(message));
    return await schnorrVerify(token, bytesToHex(hash), delegatorPubkey);
  } catch (error) {
    throw new Nip26Error(`Failed to verify delegation: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Create a delegation tag for an event
 */
export async function createDelegationTag(
  delegatorPrivateKey: string,
  delegateePubkey: string,
  conditions: string = "",
  since: number = 0,
  until: number = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30
): Promise<string[]> {
  try {
    const delegatorPubkey = getPublicKey(delegatorPrivateKey);
    const token = await createDelegation(
      delegatorPrivateKey,
      delegateePubkey,
      conditions,
      since,
      until
    );

    return [
      "delegation",
      delegatorPubkey,
      conditions,
      since.toString(),
      until.toString(),
      token,
    ];
  } catch (error) {
    throw new Nip26Error(`Failed to create delegation tag: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}
