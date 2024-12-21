// Event kind definitions
export enum EventKind {
  SET_METADATA = 0,
  TEXT_NOTE = 1,
  RECOMMEND_SERVER = 2,
  CONTACT_LIST = 3,
  ENCRYPTED_DIRECT_MESSAGE = 4,
  DELETE = 5,
  REPOST = 6,
  REACTION = 7,
  BADGE_AWARD = 8,
  ZAP_REQUEST = 9734,
  ZAP = 9735,
  CLIENT_AUTH = 22242,
  NWC_WALLET_REQUEST = 23194
}

export interface UnsignedEvent {
  pubkey: string;
  created_at: number;
  kind: EventKind;
  tags: string[][];
  content: string;
  id?: string;  // Optional ID field
  nonce?: string;  // Optional nonce for proof of work
}

export interface NostrEvent extends UnsignedEvent {
  id: string;
  sig: string;
}

export interface EventValidationResult {
  isValid: boolean;
  errors: string[];
}