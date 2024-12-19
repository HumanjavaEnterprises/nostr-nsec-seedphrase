import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { NostrEvent, UnsignedEvent } from "../types/events";
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

  // Start with nonce = 0
  let nonce = 0;
  let nonceTag = ['nonce', '0'];

  // Add or update nonce tag
  const tags = event.tags.filter(tag => tag[0] !== 'nonce');
  tags.push(nonceTag);

  // Create event with initial nonce
  let candidateEvent = {
    ...event,
    tags
  };

  // Mine until we find a valid nonce
  while (!hasValidProofOfWork(candidateEvent, difficulty)) {
    nonce++;
    nonceTag[1] = nonce.toString();
    candidateEvent.tags = [...tags.slice(0, -1), nonceTag];
  }

  // Set the event ID
  candidateEvent.id = calculateEventId(candidateEvent);

  return candidateEvent;
}

/**
 * Calculate the difficulty (number of leading zero bits) of an event ID
 * @param {string} id - The event ID in hex format
 * @returns {number} The number of leading zero bits
 */
export function getDifficulty(id: string): number {
  return countLeadingZeroes(id);
}

/**
 * Check if an event meets a target difficulty
 * @param {string} id - The event ID in hex format
 * @param {number} targetDifficulty - The target number of leading zero bits
 * @returns {boolean} True if the event meets the target difficulty
 */
export function checkDifficulty(id: string, targetDifficulty: number): boolean {
  return getDifficulty(id) >= targetDifficulty;
}

/**
 * Mine an event to achieve a target difficulty
 * @param {UnsignedEvent} event - The event to mine
 * @param {number} targetDifficulty - The target number of leading zero bits
 * @returns {UnsignedEvent} The mined event with updated nonce tag
 */
export function mineEvent(event: UnsignedEvent, targetDifficulty: number): UnsignedEvent {
  let nonce = 0;
  const tags = [...event.tags];

  // Remove any existing nonce tags
  const nonceTagIndex = tags.findIndex(tag => tag[0] === 'nonce');
  if (nonceTagIndex !== -1) {
    tags.splice(nonceTagIndex, 1);
  }

  while (true) {
    // Add nonce tag
    const nonceTag = ['nonce', nonce.toString()];
    const eventWithNonce: UnsignedEvent = {
      ...event,
      tags: [...tags, nonceTag],
    };

    // Calculate event ID
    const id = calculateEventId(eventWithNonce);

    // Check if we've reached target difficulty
    if (checkDifficulty(id, targetDifficulty)) {
      return eventWithNonce;
    }

    nonce++;
  }
}

/**
 * Mine an event asynchronously with a progress callback
 * @param {UnsignedEvent} event - The event to mine
 * @param {number} targetDifficulty - The target number of leading zero bits
 * @param {(attempts: number) => void} [progressCallback] - Optional callback for mining progress
 * @returns {Promise<UnsignedEvent>} The mined event
 */
export async function mineEventAsync(
  event: UnsignedEvent,
  targetDifficulty: number,
  progressCallback?: (attempts: number) => void
): Promise<UnsignedEvent> {
  let nonce = 0;
  const tags = [...event.tags];
  const batchSize = 1000; // Number of attempts per tick

  // Remove any existing nonce tags
  const nonceTagIndex = tags.findIndex(tag => tag[0] === 'nonce');
  if (nonceTagIndex !== -1) {
    tags.splice(nonceTagIndex, 1);
  }

  while (true) {
    for (let i = 0; i < batchSize; i++) {
      // Add nonce tag
      const nonceTag = ['nonce', nonce.toString()];
      const eventWithNonce: UnsignedEvent = {
        ...event,
        tags: [...tags, nonceTag],
      };

      // Calculate event ID
      const id = calculateEventId(eventWithNonce);

      // Check if we've reached target difficulty
      if (checkDifficulty(id, targetDifficulty)) {
        return eventWithNonce;
      }

      nonce++;
    }

    // Report progress
    if (progressCallback) {
      progressCallback(nonce);
    }

    // Allow other tasks to run
    await new Promise(resolve => setTimeout(resolve, 0));
  }
}

/**
 * Create a new event with proof of work
 * @param {string} content - The event content
 * @param {number} kind - The event kind
 * @param {string} pubkey - The event pubkey
 * @param {string[][]} tags - The event tags
 * @param {number} target - The target difficulty
 * @param {number} created_at - The event creation time
 * @returns {UnsignedEvent} The event with proof of work
 */
export function createPowEvent(
  content: string,
  kind: number,
  pubkey: string,
  tags: string[][] = [],
  target = 0,
  created_at = Math.floor(Date.now() / 1000)
): UnsignedEvent {
  const event: UnsignedEvent = {
    pubkey,
    created_at,
    kind,
    tags,
    content,
  };
  return event;
}

// Re-export utility functions
export { countLeadingZeroes };
