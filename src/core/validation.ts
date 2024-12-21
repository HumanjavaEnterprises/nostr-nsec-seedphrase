import { NostrEvent, UnsignedEvent, EventValidationResult } from '../types/events';
import { verifyEventSignature } from './event';
import * as secp256k1 from '@noble/secp256k1';
import { hexToBytes } from '../utils/encoding';
import { Point } from '@noble/secp256k1';

/**
 * Validate an unsigned event
 */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export function validateUnsignedEvent(event: UnsignedEvent): EventValidationResult {
  const errors: string[] = [];

  // Check required fields
  if (!event.pubkey) {
    errors.push('Missing public key');
  } else {
    try {
      // Validate public key format and length
      const pubkeyBytes = hexToBytes(event.pubkey);
      // Allow both compressed (33 bytes) and uncompressed (65 bytes) public keys
      if (pubkeyBytes.length === 33) {
        // Compressed public key must start with 0x02 or 0x03
        if (![0x02, 0x03].includes(pubkeyBytes[0])) {
          errors.push('Invalid compressed public key format');
        }
      } else if (pubkeyBytes.length === 65) {
        // Uncompressed public key must start with 0x04
        if (pubkeyBytes[0] !== 0x04) {
          errors.push('Invalid uncompressed public key format');
        }
      } else {
        errors.push('Invalid public key length');
      }
      
      // Verify the public key is on the curve
      try {
        Point.fromHex(event.pubkey);
      } catch {
        errors.push('Public key is not on the curve');
      }
    } catch (error) {
      errors.push('Invalid public key');
    }
  }

  if (!event.created_at) {
    errors.push('Missing creation timestamp');
  }

  if (typeof event.kind !== 'number') {
    errors.push('Missing or invalid event kind');
  }

  if (!Array.isArray(event.tags)) {
    errors.push('Missing or invalid tags array');
  } else {
    // Additional tag validation
    event.tags.forEach((tag, index) => {
      if (!Array.isArray(tag) || tag.some(item => typeof item !== 'string')) {
        errors.push(`Invalid tag format at index ${index}`);
      }
    });
  }

  if (typeof event.content !== 'string') {
    errors.push('Missing or invalid content');
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Validate a signed event
 */
export async function validateSignedEvent(event: NostrEvent): Promise<EventValidationResult> {
  // First validate as unsigned event
  const baseValidation = validateUnsignedEvent(event);
  if (!baseValidation.isValid) {
    return baseValidation;
  }

  const errors: string[] = [];

  // Check signature-specific fields
  if (!event.id) {
    errors.push('Missing event ID');
  }

  if (!event.sig) {
    errors.push('Missing signature');
  }

  // If we have all required fields, verify the signature
  if (errors.length === 0) {
    try {
      const isValid = await verifyEventSignature(event);
      if (!isValid) {
        errors.push('Invalid signature');
      }
    } catch (error) {
      errors.push(`Signature verification failed: ${error instanceof Error ? error.message : 'unknown error'}`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Validate an event (can be either signed or unsigned)
 */
export async function validateEvent(event: NostrEvent | UnsignedEvent): Promise<EventValidationResult> {
  if ('sig' in event && 'id' in event) {
    return validateSignedEvent(event as NostrEvent);
  }
  return validateUnsignedEvent(event as UnsignedEvent);
}

/**
 * Validate delegation conditions
 */
export interface DelegationConditions {
  kind?: number;
  since?: number;
  until?: number;
  delegator?: string;
}

export function isDelegationValid(conditions: DelegationConditions, event: NostrEvent): boolean {
  const now = Math.floor(Date.now() / 1000);

  if (conditions.kind !== undefined && event.kind !== conditions.kind) {
    return false;
  }

  if (conditions.since !== undefined && event.created_at < conditions.since) {
    return false;
  }

  if (conditions.until !== undefined && event.created_at > conditions.until) {
    return false;
  }

  if (conditions.delegator !== undefined) {
    const delegatorTag = event.tags.find(tag => tag[0] === 'delegation' && tag[1] === conditions.delegator);
    if (!delegatorTag) {
      return false;
    }
  }

  return true;
}