export interface UnsignedEvent {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  id?: string;  // Optional ID field
}

export interface NostrEvent extends UnsignedEvent {
  id: string;
  sig: string;
}

export interface EventValidationResult {
  isValid: boolean;
  errors: string[];
}

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
  // Add other kinds as needed
}