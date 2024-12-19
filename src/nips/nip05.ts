/**
 * NIP-05: Mapping Nostr keys to DNS-based internet identifiers
 */

export interface Nip05Response {
  names: { [username: string]: string };
  relays?: { [pubkey: string]: string[] };
}

/**
 * Verify a NIP-05 identifier
 * @param identifier - The NIP-05 identifier (e.g., "name@domain.com")
 * @param pubkey - The public key to verify
 * @returns Boolean indicating if verification was successful
 */
export async function verifyNip05(
  identifier: string,
  pubkey: string
): Promise<boolean> {
  try {
    const [name, domain] = identifier.split('@');
    if (!name || !domain) {
      return false;
    }

    const url = `https://${domain}/.well-known/nostr.json?name=${name}`;
    const response = await fetch(url);
    
    if (!response.ok) {
      return false;
    }

    const data = await response.json() as Nip05Response;
    return data.names[name]?.toLowerCase() === pubkey.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Get relays associated with a NIP-05 identifier
 * @param identifier - The NIP-05 identifier
 * @returns Array of relay URLs or null if not found
 */
export async function getNip05Relays(
  identifier: string
): Promise<string[] | null> {
  try {
    const [name, domain] = identifier.split('@');
    if (!name || !domain) {
      return null;
    }

    const url = `https://${domain}/.well-known/nostr.json?name=${name}`;
    const response = await fetch(url);
    
    if (!response.ok) {
      return null;
    }

    const data = await response.json() as Nip05Response;
    const pubkey = data.names[name];
    
    return data.relays?.[pubkey] || null;
  } catch {
    return null;
  }
}

/**
 * Format a NIP-05 identifier
 * @param name - Username part
 * @param domain - Domain part
 * @returns Formatted NIP-05 identifier
 */
export function formatNip05(name: string, domain: string): string {
  return `${name}@${domain}`;
}

/**
 * Parse a NIP-05 identifier
 * @param identifier - The NIP-05 identifier to parse
 * @returns Object containing name and domain parts
 */
export function parseNip05(identifier: string): { name: string; domain: string } | null {
  const parts = identifier.split('@');
  if (parts.length !== 2) {
    return null;
  }
  
  return {
    name: parts[0],
    domain: parts[1]
  };
}
