/**
 * @module constants
 * @description Constants used throughout the library
 */
/**
 * Standard Nostr message types as defined in NIP-01
 * @see https://github.com/nostr-protocol/nips/blob/master/01.md
 */
export declare const NOSTR_MESSAGE_TYPE: {
    readonly EVENT: "EVENT";
    readonly REQ: "REQ";
    readonly CLOSE: "CLOSE";
    readonly NOTICE: "NOTICE";
    readonly EOSE: "EOSE";
    readonly OK: "OK";
    readonly AUTH: "AUTH";
    readonly ERROR: "ERROR";
};
/**
 * Standard Nostr event kinds as defined in various NIPs
 * @see https://github.com/nostr-protocol/nips
 */
export declare const NOSTR_EVENT_KIND: {
    readonly SET_METADATA: 0;
    readonly TEXT_NOTE: 1;
    readonly RECOMMEND_SERVER: 2;
    readonly CONTACT_LIST: 3;
    readonly ENCRYPTED_DIRECT_MESSAGE: 4;
    readonly DELETE: 5;
    readonly REPOST: 6;
    readonly REACTION: 7;
    readonly BADGE_AWARD: 8;
    readonly CHANNEL_CREATE: 40;
    readonly CHANNEL_METADATA: 41;
    readonly CHANNEL_MESSAGE: 42;
    readonly CHANNEL_HIDE_MESSAGE: 43;
    readonly CHANNEL_MUTE_USER: 44;
    readonly CHANNEL_RESERVED_FIRST: 40;
    readonly CHANNEL_RESERVED_LAST: 49;
    readonly REPLACEABLE_FIRST: 10000;
    readonly REPLACEABLE_LAST: 19999;
    readonly EPHEMERAL_FIRST: 20000;
    readonly EPHEMERAL_LAST: 29999;
    readonly PARAMETERIZED_REPLACEABLE_FIRST: 30000;
    readonly PARAMETERIZED_REPLACEABLE_LAST: 39999;
};
/**
 * Standard Nostr tag types
 */
export declare const NOSTR_TAG: {
    readonly EVENT: "e";
    readonly PUBKEY: "p";
    readonly REFERENCE: "a";
    readonly DELEGATION: "delegation";
    readonly DEDUPLICATION: "d";
    readonly EXPIRATION: "expiration";
    readonly KIND: "k";
    readonly RELAY: "relay";
};
/**
 * Protocol-related constants
 */
export declare const Protocol: {
    readonly DEFAULT_RELAY_URL: "wss://relay.nostr.info";
    readonly RECONNECT_DELAY: 1000;
    readonly MAX_RECONNECT_DELAY: 30000;
    readonly PING_INTERVAL: 30000;
    readonly SUBSCRIPTION_TIMEOUT: 10000;
};
/**
 * Default values
 */
export declare const Defaults: {
    readonly KIND: 1;
    readonly CREATED_AT: () => number;
    readonly TAGS: string[][];
    readonly CONTENT: "";
};
