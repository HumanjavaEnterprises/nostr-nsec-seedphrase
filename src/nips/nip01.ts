import { UnsignedEvent, NostrEvent } from "../types/events";
import { 
  getEventHash, 
  signEvent, 
  verifyEventSignature, 
  createUnsignedEventFromPubkey 
} from "../core/event";

/**
 * Create a signed event according to NIP-01 specifications
 */
export async function createNip01SignedEvent(
  pubkey: string,
  kind: number,
  content: string,
  privateKey: string,
  tags: string[][] = []
): Promise<NostrEvent> {
  const unsignedEvent = createUnsignedEventFromPubkey(pubkey, kind, content, tags);
  return await signEvent(unsignedEvent, privateKey);
}

// Re-export core functions for backward compatibility
export { 
  getEventHash, 
  signEvent, 
  verifyEventSignature, 
  createUnsignedEventFromPubkey as createUnsignedEvent 
};