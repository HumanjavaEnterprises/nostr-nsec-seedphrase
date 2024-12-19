import { UnsignedEvent, NostrEvent, EventValidationResult } from '../types';

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export function validateUnsignedEvent(event: UnsignedEvent): EventValidationResult {
  const errors: string[] = [];
  if (!event.pubkey || event.pubkey.length !== 64) errors.push('Invalid public key');
  if (!event.created_at) errors.push('Missing creation time');
  if (typeof event.kind !== 'number') errors.push('Invalid event kind');
  if (!Array.isArray(event.tags)) errors.push('Invalid tags format');
  if (typeof event.content !== 'string') errors.push('Invalid content format');
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

export function validateSignedEvent(event: NostrEvent): EventValidationResult {
  const errors: string[] = [];
  if (!event.id || event.id.length !== 64) errors.push('Invalid event ID');
  if (!event.sig || event.sig.length !== 128) errors.push('Invalid signature');
  
  const baseValidation = validateUnsignedEvent(event);
  errors.push(...baseValidation.errors);
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

export function validateEvent(event: UnsignedEvent | NostrEvent): EventValidationResult {
  if ('sig' in event && 'id' in event) {
    return validateSignedEvent(event as NostrEvent);
  }
  return validateUnsignedEvent(event);
}

/**
 * Interface for delegation conditions
 */
export interface DelegationConditions {
  kinds?: number[];
  since?: number;
  until?: number;
}

/**
 * Check if a delegation is currently valid based on time conditions
 * @param conditions - The delegation conditions to check
 * @returns boolean indicating if the delegation is currently valid
 */
export function isDelegationValid(conditions: DelegationConditions): boolean {
  const now = Math.floor(Date.now() / 1000);
  
  // Check time-based conditions
  if (conditions.since && now < conditions.since) {
    return false;
  }
  if (conditions.until && now > conditions.until) {
    return false;
  }
  
  return true;
}