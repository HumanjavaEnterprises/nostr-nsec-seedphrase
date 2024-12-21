import { encrypt, decrypt } from '../crypto/encryption';
import { schnorrSign } from '../crypto/signing';
import { getPublicKey, validatePublicKey } from '../crypto/keys';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { toCompressed } from '../crypto/key-transforms';

export interface NostrConnectMetadata {
  name: string;
  url?: string;
  description?: string;
}

export interface RemoteSignerSession {
  id: string;
  publicKey: string;
  metadata: NostrConnectMetadata;
  permissions: Set<string>;
  createdAt: number;
  lastUsed: number;
}

export class NostrConnect {
  private privateKey: string;
  private publicKey: string;
  private metadata: NostrConnectMetadata;
  private sessions: Map<string, RemoteSignerSession>;

  constructor(privateKey: string, metadata: NostrConnectMetadata) {
    this.privateKey = privateKey;
    this.publicKey = getPublicKey(privateKey);
    this.metadata = metadata;
    this.sessions = new Map();
  }

  /**
   * Create a new remote signing session
   * @param clientPubkey - Client's public key
   * @param clientMetadata - Client's metadata
   * @param permissions - Requested permissions
   * @returns Session information
   */
  createSession(
    clientPubkey: string,
    clientMetadata: NostrConnectMetadata,
    permissions: string[]
  ): RemoteSignerSession {
    const session: RemoteSignerSession = {
      id: bytesToHex(sha256(new TextEncoder().encode(`${this.publicKey}:${clientPubkey}:${Date.now()}`))),
      publicKey: clientPubkey,
      metadata: clientMetadata,
      permissions: new Set(permissions),
      createdAt: Math.floor(Date.now() / 1000),
      lastUsed: Math.floor(Date.now() / 1000)
    };

    this.sessions.set(session.id, session);
    return session;
  }

  /**
   * Handle a remote signing request
   * @param sessionId - Session ID
   * @param request - The request to handle
   * @returns Response to the request
   */
  async handleRequest(
    sessionId: string,
    request: {
      id: string;
      method: string;
      params: any;
    }
  ): Promise<any> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    if (!session.permissions.has(request.method)) {
      throw new Error('Permission denied');
    }

    session.lastUsed = Math.floor(Date.now() / 1000);

    switch (request.method) {
      case 'sign_event':
        return this.handleSignEvent(session, request.params);
      case 'get_public_key':
        return this.publicKey;
      case 'connect':
        return {
          publicKey: this.publicKey,
          metadata: this.metadata
        };
      default:
        throw new Error('Unknown method');
    }
  }

  /**
   * Handle a sign event request
   * @param session - Current session
   * @param params - Request parameters
   * @returns Signed event
   */
  private async handleSignEvent(session: RemoteSignerSession, params: any): Promise<any> {
    if (!params.event) {
      throw new Error('Missing event parameter');
    }

    const event = params.event;
    
    // Validate event structure
    if (!event.pubkey || !event.created_at || !event.kind || !Array.isArray(event.tags) || !event.content) {
      throw new Error('Invalid event structure');
    }

    // Verify permissions based on event kind
    if (!session.permissions.has('sign_event') && !session.permissions.has(`sign_event:${event.kind}`)) {
      throw new Error('Permission denied for event signing');
    }

    // Handle POW if difficulty is specified
    if (params.difficulty) {
      let nonce = 0;
      let eventHash: string;
      
      do {
        event.tags.push(['nonce', nonce.toString()]);
        eventHash = bytesToHex(sha256(Buffer.from(JSON.stringify([
          0,
          event.pubkey,
          event.created_at,
          event.kind,
          event.tags,
          event.content
        ]))));
        
        if (this.countLeadingZeros(eventHash) >= params.difficulty) {
          break;
        }
        
        // Remove the nonce tag for the next attempt
        event.tags.pop();
        nonce++;
      } while (nonce < Number.MAX_SAFE_INTEGER);
      
      if (nonce >= Number.MAX_SAFE_INTEGER) {
        throw new Error('Could not find valid nonce for POW');
      }
    }

    const eventHash = sha256(Buffer.from(JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content
    ])));

    try {
      const signature = await schnorrSign(bytesToHex(eventHash), this.privateKey);
      return { sig: signature };
    } catch (error: any) {
      throw new Error(`Failed to sign event: ${error.message}`);
    }
  }

  /**
   * Count leading zeros in a hex string
   * @param hex - Hex string to count leading zeros
   * @returns Number of leading zeros
   */
  private countLeadingZeros(hex: string): number {
    let count = 0;
    for (let i = 0; i < hex.length; i++) {
      const nibble = parseInt(hex[i], 16);
      if (nibble === 0) {
        count += 4;
      } else {
        count += Math.clz32(nibble) - 28;
        break;
      }
    }
    return count;
  }

  /**
   * Send an encrypted message to a client
   * @param clientPubkey - Client's public key or session ID
   * @param message - Message to send
   * @returns Encrypted message
   */
  async sendMessage(clientPubkey: string, message: any): Promise<string> {
    // Check if this is a session ID instead of a public key
    if (clientPubkey.length < 64) {
      const session = this.sessions.get(clientPubkey);
      if (!session) {
        throw new Error('Session not found');
      }
      clientPubkey = session.publicKey;
    }

    try {
      // Validate and convert public key to proper format
      if (!validatePublicKey(clientPubkey)) {
        throw new Error('Invalid client public key');
      }

      // Convert to compressed format before encryption
      const compressedPubKey = bytesToHex(toCompressed(clientPubkey));

      return await encrypt(
        JSON.stringify(message),
        this.privateKey,
        compressedPubKey
      );
    } catch (error: any) {
      throw new Error(`Failed to encrypt message: ${error.message}`);
    }
  }

  /**
   * Receive and decrypt a message from a client
   * @param clientPubkey - Client's public key
   * @param encryptedMessage - Encrypted message
   * @returns Decrypted message
   */
  async receiveMessage(clientPubkey: string, encryptedMessage: string): Promise<any> {
    // Check if this is a session ID instead of a public key
    if (clientPubkey.length < 64) {
      const session = this.sessions.get(clientPubkey);
      if (!session) {
        throw new Error('Session not found');
      }
      clientPubkey = session.publicKey;
      
      // Update last used timestamp
      session.lastUsed = Date.now();
      this.sessions.set(clientPubkey, session);
    }

    try {
      // Validate and convert public key to proper format
      if (!validatePublicKey(clientPubkey)) {
        throw new Error('Invalid client public key');
      }

      // Convert to compressed format before decryption
      const compressedPubKey = bytesToHex(toCompressed(clientPubkey));

      const decrypted = await decrypt(
        encryptedMessage,
        this.privateKey,
        compressedPubKey
      );
      return JSON.parse(decrypted);
    } catch (error: any) {
      throw new Error(`Failed to decrypt message: ${error.message}`);
    }
  }

  /**
   * Remove a session
   * @param sessionId - Session ID to remove
   */
  removeSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Get all active sessions
   * @returns Map of active sessions
   */
  getSessions(): Map<string, RemoteSignerSession> {
    return new Map(this.sessions);
  }

  /**
   * Clean up expired sessions
   * @param maxAge - Maximum session age in seconds
   */
  cleanupSessions(maxAge: number): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [id, session] of this.sessions) {
      if (now - session.lastUsed > maxAge) {
        this.sessions.delete(id);
      }
    }
  }
}
