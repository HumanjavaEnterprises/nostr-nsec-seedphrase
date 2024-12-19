import { encrypt, decrypt } from './nip44';
import { schnorrSign } from '../crypto/signing';
import { getPublicKey } from '../crypto/keys';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

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
        return this.handleSignEvent(request.params);
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
   * Handle event signing request
   * @param params - Event parameters
   * @returns Signed event
   */
  private async handleSignEvent(params: any): Promise<any> {
    const event = params;
    const eventHash = sha256(Buffer.from(JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content
    ])));

    const signature = await schnorrSign(eventHash, this.privateKey);
    
    return {
      ...event,
      sig: signature  // schnorrSign already returns hex string
    };
  }

  /**
   * Send an encrypted message to a client
   * @param sessionId - Session ID
   * @param message - Message to send
   * @returns Encrypted message
   */
  async sendMessage(sessionId: string, message: any): Promise<string> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    return encrypt(
      JSON.stringify(message),
      this.privateKey,
      session.publicKey
    );
  }

  /**
   * Receive and decrypt a message from a client
   * @param sessionId - Session ID
   * @param encryptedMessage - Encrypted message
   * @returns Decrypted message
   */
  async receiveMessage(sessionId: string, encryptedMessage: string): Promise<any> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    const decrypted = decrypt(
      encryptedMessage,
      this.privateKey,
      session.publicKey
    );

    return JSON.parse(decrypted);
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
