import { NostrEvent, UnsignedEvent } from '../types/events.js';
/**
 * Creates a new signed Nostr event
 * @param {string} content - The event content
 * @param {number} kind - The event kind (1 for text note, etc.)
 * @param {string} privateKey - The hex-encoded private key to sign with
 * @param {string[][]} [tags=[]] - Optional event tags
 * @returns {Promise<NostrEvent>} The signed event
 * @throws {Error} If event creation or signing fails
 * @example
 * const event = await createEvent(
 *   "Hello Nostr!",
 *   1,
 *   privateKey,
 *   [["t", "nostr"]]
 * );
 * console.log(event); // complete signed event
 */
export declare function createEvent(content: string, kind: number, privateKey: string, tags?: string[][]): Promise<NostrEvent>;
/**
 * Validates a Nostr event's structure and data types
 * @param {NostrEvent} event - The event to validate
 * @returns {boolean} True if the event is valid, false otherwise
 */
export declare function validateEventStructure(event: NostrEvent): boolean;
/**
 * Serializes an event for hashing or transmission
 * @param {UnsignedEvent} event - The event to serialize
 * @returns {string} JSON string of the event in the Nostr format
 */
export declare function serializeEvent(event: UnsignedEvent): string;
/**
 * Gets the creation date of an event as a Date object
 * @param {NostrEvent} event - The event to get the date from
 * @returns {Date} The creation date
 */
export declare function getEventDate(event: NostrEvent): Date;
/**
 * Extracts tags of a specific type from an event
 * @param {NostrEvent} event - The event to extract tags from
 * @param {string} tagName - The tag identifier to look for
 * @returns {string[][]} Array of matching tags
 */
export declare function getEventTags(event: NostrEvent, tagName: string): string[][];
/**
 * Checks if an event has a specific tag
 * @param {NostrEvent} event - The event to check
 * @param {string} tagName - The tag identifier to look for
 * @returns {boolean} True if the event has the tag
 */
export declare function hasEventTag(event: NostrEvent, tagName: string): boolean;
