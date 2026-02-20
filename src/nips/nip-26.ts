/**
 * @module nips/nip-26
 * @description NIP-26 Delegated Event Signing implementation
 * @see https://github.com/nostr-protocol/nips/blob/master/26.md
 */

import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { logger } from "../utils/logger.js";
import { ValidationResult } from "../types/index.js";

export interface DelegationConditions {
  /** Unix timestamp after which delegation is valid */
  since?: number;
  /** Unix timestamp until which delegation is valid */
  until?: number;
  /** Event kinds that can be signed */
  kinds?: number[];
}

export interface DelegationToken {
  /** Public key of the delegator */
  delegator: string;
  /** Public key of the delegatee */
  delegatee: string;
  /** Conditions of the delegation */
  conditions: DelegationConditions;
  /** Token signature */
  signature: string;
}

/**
 * Creates a delegation token string
 * @param conditions - Delegation conditions
 * @returns Delegation token string
 */
function createDelegationString(
  delegator: string,
  delegatee: string,
  conditions: DelegationConditions,
): string {
  const parts = ["nostr", "delegation", delegator, delegatee];

  if (conditions.kinds) {
    parts.push(`kinds=${conditions.kinds.join(",")}`);
  }
  if (conditions.since) {
    parts.push(`created_at>${conditions.since}`);
  }
  if (conditions.until) {
    parts.push(`created_at<${conditions.until}`);
  }

  return parts.join(":");
}

/**
 * Creates a delegation token
 * @param delegatee - Public key of the delegatee
 * @param conditions - Delegation conditions
 * @param delegatorPrivateKey - Private key of the delegator
 * @returns Delegation token
 */
export async function createDelegation(
  delegatee: string,
  conditions: DelegationConditions,
  delegatorPrivateKey: string,
): Promise<DelegationToken> {
  try {
    // Get delegator's public key
    const delegator = bytesToHex(schnorr.getPublicKey(delegatorPrivateKey));

    // Create delegation string
    const tokenString = createDelegationString(
      delegator,
      delegatee,
      conditions,
    );

    // Sign the token
    const messageHash = sha256(new TextEncoder().encode(tokenString));
    const signature = await schnorr.sign(messageHash, delegatorPrivateKey);

    logger.log("Created delegation token");
    return {
      delegator,
      delegatee,
      conditions,
      signature: bytesToHex(signature),
    };
  } catch (error) {
    logger.error("Failed to create delegation token:", error?.toString());
    throw error;
  }
}

/**
 * Verifies a delegation token
 * @param token - The delegation token to verify
 * @param now - Current Unix timestamp in seconds (optional, defaults to current time)
 * @returns Result of the validation
 */
async function verifyDelegation(
  token: string,
  now?: number,
): Promise<ValidationResult> {
  try {
    const tokenObject: DelegationToken = JSON.parse(token);
    // Check conditions
    if (now) {
      if (tokenObject.conditions.since && now < tokenObject.conditions.since) {
        return {
          isValid: false,
          error: "Event timestamp before delegation validity period",
        };
      }
      if (tokenObject.conditions.until && now > tokenObject.conditions.until) {
        return {
          isValid: false,
          error: "Event timestamp after delegation validity period",
        };
      }
    }

    // Verify signature
    const tokenString = createDelegationString(
      tokenObject.delegator,
      tokenObject.delegatee,
      tokenObject.conditions,
    );
    const messageHash = sha256(new TextEncoder().encode(tokenString));

    const isValid = await schnorr.verify(
      tokenObject.signature,
      messageHash,
      tokenObject.delegator,
    );

    return {
      isValid,
      error: isValid ? undefined : "Invalid delegation signature",
    };
  } catch (error) {
    logger.error("Failed to verify delegation:", error?.toString());
    return {
      isValid: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Checks if a delegation token is currently valid
 * @param token - The delegation token to check
 * @param now - Current Unix timestamp in seconds (optional, defaults to current time)
 * @returns True if the delegation is valid
 */
export async function isValidDelegation(
  token: string,
  now?: number,
): Promise<boolean> {
  const result = await verifyDelegation(token, now);
  return result.isValid;
}

/**
 * Gets the expiration time of a delegation token
 * @param token - Delegation token
 * @returns Expiration timestamp or undefined if no expiration
 */
export function getDelegationExpiry(token: string): number | undefined {
  const tokenObject: DelegationToken = JSON.parse(token);
  return tokenObject.conditions.until;
}
