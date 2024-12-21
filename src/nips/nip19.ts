import {
  PREFIXES,
  NostrPrefix,
  EncodingError,
  hexToBytes,
  bytesToHex,
  encodeBech32,
  decodeBech32
} from '../crypto/encoding';

/**
 * NIP-19: bech32-encoded entities
 * @see https://github.com/nostr-protocol/nips/blob/master/19.md
 */

export interface TLVEntry {
  type: number;
  length: number;
  value: Uint8Array;
}

export interface ProfileData {
  pubkey: string;
  relays: string[];
}

export interface EventData {
  id: string;
  relays: string[];
  author?: string;
}

/**
 * Parse TLV (Type-Length-Value) entries from bytes
 */
function parseTLV(bytes: Uint8Array): TLVEntry[] {
  const entries: TLVEntry[] = [];
  let pos = 0;

  while (pos < bytes.length) {
    const type = bytes[pos++];
    if (pos >= bytes.length) break;

    const length = bytes[pos++];
    if (pos + length > bytes.length) break;

    const value = bytes.slice(pos, pos + length);
    pos += length;

    entries.push({ type, length, value });
  }

  return entries;
}

/**
 * Create TLV bytes from entries
 */
function createTLV(entries: TLVEntry[]): Uint8Array {
  const totalLength = entries.reduce((sum, { length }) => sum + 2 + length, 0);
  const bytes = new Uint8Array(totalLength);
  let pos = 0;

  for (const { type, length, value } of entries) {
    bytes[pos++] = type;
    bytes[pos++] = length;
    bytes.set(value, pos);
    pos += length;
  }

  return bytes;
}

/**
 * Encode hex to npub format
 */
export function npubEncode(hex: string): string {
  try {
    const data = hexToBytes(hex);
    return encodeBech32(PREFIXES.NPUB, data);
  } catch (error) {
    throw new EncodingError(`Failed to encode npub: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Encode hex to nsec format
 */
export function nsecEncode(hex: string): string {
  try {
    const data = hexToBytes(hex);
    return encodeBech32(PREFIXES.NSEC, data);
  } catch (error) {
    throw new EncodingError(`Failed to encode nsec: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Encode hex to note format
 */
export function noteEncode(hex: string): string {
  try {
    const data = hexToBytes(hex);
    return encodeBech32(PREFIXES.NOTE, data);
  } catch (error) {
    throw new EncodingError(`Failed to encode note: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decode npub format to hex
 */
export function npubDecode(npub: string): string {
  try {
    const { prefix, data } = decodeBech32(npub);
    if (prefix !== PREFIXES.NPUB) {
      throw new EncodingError('Invalid npub prefix');
    }
    return bytesToHex(data);
  } catch (error) {
    throw new EncodingError(`Failed to decode npub: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decode nsec format to hex
 */
export function nsecDecode(nsec: string): string {
  try {
    const { prefix, data } = decodeBech32(nsec);
    if (prefix !== PREFIXES.NSEC) {
      throw new EncodingError('Invalid nsec prefix');
    }
    return bytesToHex(data);
  } catch (error) {
    throw new EncodingError(`Failed to decode nsec: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decode note format to hex
 */
export function noteDecode(note: string): string {
  try {
    const { prefix, data } = decodeBech32(note);
    if (prefix !== PREFIXES.NOTE) {
      throw new EncodingError('Invalid note prefix');
    }
    return bytesToHex(data);
  } catch (error) {
    throw new EncodingError(`Failed to decode note: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Encode a profile
 */
export function encodeProfile(pubkey: string, relays: string[] = []): string {
  try {
    const entries: TLVEntry[] = [
      {
        type: 0,
        length: 32,
        value: hexToBytes(pubkey)
      },
      ...relays.map(relay => ({
        type: 1,
        length: relay.length,
        value: new TextEncoder().encode(relay)
      }))
    ];

    const data = createTLV(entries);
    return encodeBech32(PREFIXES.NPROFILE, data);
  } catch (error) {
    throw new EncodingError(`Failed to encode profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decode a profile
 */
export function decodeProfile(nprofile: string): ProfileData {
  try {
    const { prefix, data } = decodeBech32(nprofile);
    if (prefix !== PREFIXES.NPROFILE) {
      throw new EncodingError('Invalid nprofile prefix');
    }

    const entries = parseTLV(data);
    const pubkeyEntry = entries.find(e => e.type === 0);
    if (!pubkeyEntry) {
      throw new EncodingError('Missing pubkey in nprofile');
    }

    const relayEntries = entries.filter(e => e.type === 1);
    const relays = relayEntries.map(e => new TextDecoder().decode(e.value));

    return {
      pubkey: bytesToHex(pubkeyEntry.value),
      relays
    };
  } catch (error) {
    throw new EncodingError(`Failed to decode profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Encode an event reference
 */
export function encodeEvent(id: string, relays: string[] = [], author?: string): string {
  try {
    const entries: TLVEntry[] = [
      {
        type: 0,
        length: 32,
        value: hexToBytes(id)
      },
      ...relays.map(relay => ({
        type: 1,
        length: relay.length,
        value: new TextEncoder().encode(relay)
      }))
    ];

    if (author) {
      entries.push({
        type: 2,
        length: 32,
        value: hexToBytes(author)
      });
    }

    const data = createTLV(entries);
    return encodeBech32(PREFIXES.NEVENT, data);
  } catch (error) {
    throw new EncodingError(`Failed to encode event: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Decode an event reference
 */
export function decodeEvent(nevent: string): EventData {
  try {
    const { prefix, data } = decodeBech32(nevent);
    if (prefix !== PREFIXES.NEVENT) {
      throw new EncodingError('Invalid nevent prefix');
    }

    const entries = parseTLV(data);
    const idEntry = entries.find(e => e.type === 0);
    if (!idEntry) {
      throw new EncodingError('Missing id in nevent');
    }

    const relayEntries = entries.filter(e => e.type === 1);
    const relays = relayEntries.map(e => new TextDecoder().decode(e.value));

    const authorEntry = entries.find(e => e.type === 2);
    const author = authorEntry ? bytesToHex(authorEntry.value) : undefined;

    return {
      id: bytesToHex(idEntry.value),
      relays,
      author
    };
  } catch (error) {
    throw new EncodingError(`Failed to decode event: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Export convenience functions for backward compatibility
export const hexToNpub = npubEncode;
export const hexToNsec = nsecEncode;
export const hexToNote = noteEncode;
export const npubToHex = npubDecode;
export const nsecToHex = nsecDecode;
export const noteToHex = noteDecode;

/**
 * Decode any bech32-encoded Nostr identifier
 */
export function decodeNip19(nip19: string): { type: NostrPrefix; data: string | ProfileData | EventData } {
  try {
    const { prefix, data } = decodeBech32(nip19);

    switch (prefix) {
      case PREFIXES.NPUB:
        return { type: prefix, data: bytesToHex(data) };
      case PREFIXES.NSEC:
        return { type: prefix, data: bytesToHex(data) };
      case PREFIXES.NOTE:
        return { type: prefix, data: bytesToHex(data) };
      case PREFIXES.NPROFILE:
        return { type: prefix, data: decodeProfile(nip19) };
      case PREFIXES.NEVENT:
        return { type: prefix, data: decodeEvent(nip19) };
      default:
        throw new EncodingError('Unknown NIP-19 prefix');
    }
  } catch (error) {
    throw new EncodingError(`Failed to decode NIP-19: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}
