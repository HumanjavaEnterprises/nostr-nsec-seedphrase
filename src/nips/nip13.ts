import { UnsignedEvent } from "../types/events";
import { calculateEventId } from "../crypto/hashing";
import { countLeadingZeroes } from "../utils/bits";

/**
 * NIP-13: Proof of Work
 * @see https://github.com/nostr-protocol/nips/blob/master/13.md
 */

/**
 * Check if an event has valid proof of work
 * @param {UnsignedEvent} event - The event to check
 * @param {number} difficulty - The required difficulty in bits
 * @returns {boolean} True if the event has valid proof of work
 */
export function hasValidProofOfWork(event: UnsignedEvent, difficulty: number): boolean {
  const id = calculateEventId(event);
  return countLeadingZeroes(id) >= difficulty;
}

/**
 * Generate proof of work for an event
 * @param {UnsignedEvent} event - The event to mine
 * @param {number} difficulty - The required difficulty in bits
 * @returns {Promise<UnsignedEvent>} The event with proof of work
 */
export async function generateProofOfWork(event: UnsignedEvent, difficulty: number): Promise<UnsignedEvent> {
  if (difficulty < 0) {
    throw new Error("Difficulty must be non-negative");
  }

  const mined = await mineEventAsync(event, difficulty);
  return mined;
}

/**
 * Mine an event to achieve a target difficulty
 * @param {UnsignedEvent} event - The event to mine
 * @param {number} targetDifficulty - The target number of leading zero bits
 * @returns {UnsignedEvent} The mined event with updated nonce tag
 */
export function mineEvent(event: UnsignedEvent, targetDifficulty: number): UnsignedEvent {
  let nonce = 0;
  let id: string;
  
  do {
    event.nonce = nonce.toString();
    id = calculateEventId(event);
    nonce++;
  } while (countLeadingZeroes(id) < targetDifficulty);
  
  return event;
}

/**
 * Mine an event asynchronously with a progress callback
 * @param {UnsignedEvent} event - The event to mine
 * @param {number} targetDifficulty - The target number of leading zero bits
 * @param {number} batchSize - Number of attempts per batch
 * @returns {Promise<UnsignedEvent>} The mined event
 */
export async function mineEventAsync(
  event: UnsignedEvent,
  targetDifficulty: number,
  batchSize: number = 1000
): Promise<UnsignedEvent> {
  if (targetDifficulty < 0) {
    throw new Error('Difficulty must be non-negative');
  }

  let nonce = 0;
  let id: string;
  
  // If target difficulty is 0, no mining needed
  if (targetDifficulty <= 0) {
    event.nonce = '0';
    return event;
  }

  // Try nonces until we find one that meets the difficulty
  do {
    event.nonce = nonce.toString();
    id = calculateEventId(event);
    
    if (countLeadingZeroes(id) >= targetDifficulty) {
      return event;
    }
    nonce++;
    
    // Yield to event loop every batchSize attempts
    if (nonce % batchSize === 0) {
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  } while (nonce < Number.MAX_SAFE_INTEGER);
  
  // If we reach here, we couldn't find a valid nonce
  throw new Error('Could not find valid nonce');
}

/**
 * Create a new event with proof of work
 * @param {string} content - The event content
 * @param {number} kind - The event kind
 * @param {string} pubkey - The event pubkey
 * @param {string[][]} tags - The event tags
 * @param {number} created_at - The event creation time
 * @returns {UnsignedEvent} The event with proof of work
 */
export function createPowEvent(
  content: string,
  kind: number,
  pubkey: string,
  tags: string[][] = [],
  created_at = Math.floor(Date.now() / 1000)
): UnsignedEvent {
  return {
    pubkey,
    created_at,
    kind,
    tags,
    content,
    nonce: '0'
  };
}

// Re-export utility functions
export { countLeadingZeroes };
