"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createEvent = createEvent;
exports.validateEventStructure = validateEventStructure;
exports.serializeEvent = serializeEvent;
exports.getEventDate = getEventDate;
exports.getEventTags = getEventTags;
exports.hasEventTag = hasEventTag;
const pino_1 = require("pino");
const crypto_js_1 = require("./crypto.js");
const keys_js_1 = require("./keys.js");
const logger = (0, pino_1.pino)({
    level: process.env.LOG_LEVEL || "info",
    transport: {
        target: "pino-pretty",
        options: {
            colorize: true,
        },
    },
});
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
async function createEvent(content, kind, privateKey, tags = []) {
    try {
        // Create unsigned event
        const unsignedEvent = {
            pubkey: (0, keys_js_1.getPublicKey)(privateKey),
            created_at: Math.floor(Date.now() / 1000),
            kind,
            tags,
            content,
        };
        // Get event hash and signature
        const id = (0, crypto_js_1.getEventHash)(unsignedEvent);
        const sig = await (0, crypto_js_1.signEvent)(unsignedEvent, privateKey);
        // Return complete signed event
        return {
            ...unsignedEvent,
            id,
            sig,
        };
    }
    catch (error) {
        logger.error('Failed to create event:', error);
        throw new Error('Failed to create event');
    }
}
/**
 * Validates a Nostr event's structure and data types
 * @param {NostrEvent} event - The event to validate
 * @returns {boolean} True if the event is valid, false otherwise
 */
function validateEventStructure(event) {
    try {
        // Check required fields exist
        if (!event.id || !event.pubkey || !event.sig) {
            return false;
        }
        // Validate field types
        if (typeof event.id !== 'string' ||
            typeof event.pubkey !== 'string' ||
            typeof event.created_at !== 'number' ||
            typeof event.kind !== 'number' ||
            !Array.isArray(event.tags) ||
            typeof event.content !== 'string' ||
            typeof event.sig !== 'string') {
            return false;
        }
        // Validate field formats
        if (!/^[0-9a-f]{64}$/.test(event.id) ||
            !/^[0-9a-f]{64}$/.test(event.pubkey) ||
            !/^[0-9a-f]{128}$/.test(event.sig)) {
            return false;
        }
        // Validate tags structure
        if (!event.tags.every(tag => Array.isArray(tag) && tag.every(item => typeof item === 'string'))) {
            return false;
        }
        return true;
    }
    catch (error) {
        logger.error('Failed to validate event structure:', error);
        return false;
    }
}
/**
 * Serializes an event for hashing or transmission
 * @param {UnsignedEvent} event - The event to serialize
 * @returns {string} JSON string of the event in the Nostr format
 */
function serializeEvent(event) {
    try {
        return JSON.stringify([
            0,
            event.pubkey,
            event.created_at,
            event.kind,
            event.tags,
            event.content,
        ]);
    }
    catch (error) {
        logger.error('Failed to serialize event:', error);
        throw new Error('Failed to serialize event');
    }
}
/**
 * Gets the creation date of an event as a Date object
 * @param {NostrEvent} event - The event to get the date from
 * @returns {Date} The creation date
 */
function getEventDate(event) {
    return new Date(event.created_at * 1000);
}
/**
 * Extracts tags of a specific type from an event
 * @param {NostrEvent} event - The event to extract tags from
 * @param {string} tagName - The tag identifier to look for
 * @returns {string[][]} Array of matching tags
 */
function getEventTags(event, tagName) {
    return event.tags.filter(tag => tag[0] === tagName);
}
/**
 * Checks if an event has a specific tag
 * @param {NostrEvent} event - The event to check
 * @param {string} tagName - The tag identifier to look for
 * @returns {boolean} True if the event has the tag
 */
function hasEventTag(event, tagName) {
    return event.tags.some(tag => tag[0] === tagName);
}
