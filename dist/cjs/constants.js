"use strict";
/**
 * @module constants
 * @description Constants used throughout the library
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.Defaults = exports.Protocol = exports.NOSTR_TAG = exports.NOSTR_EVENT_KIND = exports.NOSTR_MESSAGE_TYPE = void 0;
/**
 * Standard Nostr message types as defined in NIP-01
 * @see https://github.com/nostr-protocol/nips/blob/master/01.md
 */
exports.NOSTR_MESSAGE_TYPE = {
    EVENT: 'EVENT',
    REQ: 'REQ',
    CLOSE: 'CLOSE',
    NOTICE: 'NOTICE',
    EOSE: 'EOSE',
    OK: 'OK',
    AUTH: 'AUTH',
    ERROR: 'ERROR'
};
/**
 * Standard Nostr event kinds as defined in various NIPs
 * @see https://github.com/nostr-protocol/nips
 */
exports.NOSTR_EVENT_KIND = {
    SET_METADATA: 0,
    TEXT_NOTE: 1,
    RECOMMEND_SERVER: 2,
    CONTACT_LIST: 3,
    ENCRYPTED_DIRECT_MESSAGE: 4,
    DELETE: 5,
    REPOST: 6,
    REACTION: 7,
    BADGE_AWARD: 8,
    CHANNEL_CREATE: 40,
    CHANNEL_METADATA: 41,
    CHANNEL_MESSAGE: 42,
    CHANNEL_HIDE_MESSAGE: 43,
    CHANNEL_MUTE_USER: 44,
    CHANNEL_RESERVED_FIRST: 40,
    CHANNEL_RESERVED_LAST: 49,
    REPLACEABLE_FIRST: 10000,
    REPLACEABLE_LAST: 19999,
    EPHEMERAL_FIRST: 20000,
    EPHEMERAL_LAST: 29999,
    PARAMETERIZED_REPLACEABLE_FIRST: 30000,
    PARAMETERIZED_REPLACEABLE_LAST: 39999
};
/**
 * Standard Nostr tag types
 */
exports.NOSTR_TAG = {
    EVENT: 'e',
    PUBKEY: 'p',
    REFERENCE: 'a',
    DELEGATION: 'delegation',
    DEDUPLICATION: 'd',
    EXPIRATION: 'expiration',
    KIND: 'k',
    RELAY: 'relay'
};
/**
 * Protocol-related constants
 */
exports.Protocol = {
    DEFAULT_RELAY_URL: 'wss://relay.nostr.info',
    RECONNECT_DELAY: 1000,
    MAX_RECONNECT_DELAY: 30000,
    PING_INTERVAL: 30000,
    SUBSCRIPTION_TIMEOUT: 10000,
};
/**
 * Default values
 */
exports.Defaults = {
    KIND: exports.NOSTR_EVENT_KIND.TEXT_NOTE,
    CREATED_AT: () => Math.floor(Date.now() / 1000),
    TAGS: [],
    CONTENT: '',
};
