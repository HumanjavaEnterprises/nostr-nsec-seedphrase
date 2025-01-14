/**
 * @module nips/nip-26
 * @description NIP-26 Delegated Event Signing implementation
 * @see https://github.com/nostr-protocol/nips/blob/master/26.md
 */
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
 * Creates a delegation token
 * @param delegatee - Public key of the delegatee
 * @param conditions - Delegation conditions
 * @param delegatorPrivateKey - Private key of the delegator
 * @returns Delegation token
 */
export declare function createDelegation(delegatee: string, conditions: DelegationConditions, delegatorPrivateKey: string): Promise<DelegationToken>;
/**
 * Checks if a delegation token is currently valid
 * @param token - The delegation token to check
 * @param now - Current Unix timestamp in seconds (optional, defaults to current time)
 * @returns True if the delegation is valid
 */
export declare function isValidDelegation(token: string, now?: number): Promise<boolean>;
/**
 * Gets the expiration time of a delegation token
 * @param token - Delegation token
 * @returns Expiration timestamp or undefined if no expiration
 */
export declare function getDelegationExpiry(token: string): number | undefined;
