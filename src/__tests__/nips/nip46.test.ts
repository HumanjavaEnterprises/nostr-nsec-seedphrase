import { describe, it, expect, beforeEach } from 'vitest';
import { generatePrivateKey, getPublicKey } from '../../crypto/keys';
import { NostrConnect, NostrConnectMetadata } from '../../nips/nip46';

describe('NIP-46: Nostr Connect', () => {
  let signer: NostrConnect;
  let signerMetadata: NostrConnectMetadata;
  let clientPrivateKey: string;
  let clientPublicKey: string;
  let clientMetadata: NostrConnectMetadata;

  beforeEach(() => {
    signerMetadata = {
      name: 'Test Signer',
      description: 'A test signer implementation'
    };
    
    const signerPrivateKey = generatePrivateKey();
    signer = new NostrConnect(signerPrivateKey, signerMetadata);
    
    clientPrivateKey = generatePrivateKey();
    clientPublicKey = getPublicKey(clientPrivateKey);
    clientMetadata = {
      name: 'Test Client',
      url: 'https://testclient.com',
      description: 'A test client'
    };
  });

  describe('Session Management', () => {
    it('should create a new session', () => {
      const permissions = ['sign_event', 'get_public_key'];
      
      const session = signer.createSession(
        clientPublicKey,
        clientMetadata,
        permissions
      );
      
      expect(session).toBeDefined();
      expect(session.publicKey).toBe(clientPublicKey);
      expect(session.metadata).toEqual(clientMetadata);
      expect(session.permissions.size).toBe(permissions.length);
      permissions.forEach(perm => {
        expect(session.permissions.has(perm)).toBe(true);
      });
    });

    it('should handle multiple sessions', () => {
      const session1 = signer.createSession(
        clientPublicKey,
        clientMetadata,
        ['sign_event']
      );
      
      const otherClientKey = getPublicKey(generatePrivateKey());
      const session2 = signer.createSession(
        otherClientKey,
        { name: 'Other Client' },
        ['get_public_key']
      );
      
      const sessions = signer.getSessions();
      expect(sessions.size).toBe(2);
      expect(sessions.get(session1.id)).toBeDefined();
      expect(sessions.get(session2.id)).toBeDefined();
    });

    it('should remove sessions', () => {
      const session = signer.createSession(
        clientPublicKey,
        clientMetadata,
        ['sign_event']
      );
      
      signer.removeSession(session.id);
      
      const sessions = signer.getSessions();
      expect(sessions.size).toBe(0);
    });

    it('should cleanup expired sessions', () => {
      const session = signer.createSession(
        clientPublicKey,
        clientMetadata,
        ['sign_event']
      );
      
      // Simulate session expiration
      const maxAge = 3600; // 1 hour
      const originalDateNow = Date.now;
      Date.now = () => {
        return (session.createdAt + maxAge + 1) * 1000;
      };
      
      signer.cleanupSessions(maxAge);
      
      Date.now = originalDateNow;
      
      const sessions = signer.getSessions();
      expect(sessions.size).toBe(0);
    });
  });

  describe('Request Handling', () => {
    let sessionId: string;

    beforeEach(() => {
      const session = signer.createSession(
        clientPublicKey,
        clientMetadata,
        ['sign_event', 'get_public_key', 'connect']
      );
      sessionId = session.id;
    });

    it('should handle get_public_key request', async () => {
      const request = {
        id: '1',
        method: 'get_public_key',
        params: {}
      };
      
      const response = await signer.handleRequest(sessionId, request);
      expect(typeof response).toBe('string');
    });

    it('should handle sign_event request', async () => {
      const event = {
        pubkey: clientPublicKey,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'Hello World'
      };

      const request = {
        id: '2',
        method: 'sign_event',
        params: { event }
      };
      
      const response = await signer.handleRequest(sessionId, request);
      expect(response.sig).toBeDefined();
    });

    it('should reject requests without permission', async () => {
      // Create session with limited permissions
      const limitedSession = signer.createSession(
        clientPublicKey,
        clientMetadata,
        ['get_public_key']
      );
      
      const request = {
        id: '3',
        method: 'sign_event',
        params: { event: {} }
      };
      
      await expect(signer.handleRequest(limitedSession.id, request))
        .rejects
        .toThrow('Permission denied');
    });
  });

  describe('Encrypted Communication', () => {
    let sessionId: string;

    beforeEach(() => {
      const session = signer.createSession(
        clientPublicKey,
        clientMetadata,
        ['sign_event']
      );
      sessionId = session.id;
    });

    it('should encrypt and decrypt messages', async () => {
      const message = { type: 'test', content: 'Hello World' };
      
      const encrypted = await signer.sendMessage(sessionId, message);
      expect(typeof encrypted).toBe('string');
      
      const decrypted = await signer.receiveMessage(sessionId, encrypted);
      expect(decrypted).toEqual(message);
    });

    it('should reject messages for invalid sessions', async () => {
      const message = { type: 'test', content: 'Hello World' };
      
      await expect(signer.sendMessage('invalid-session', message))
        .rejects
        .toThrow('Session not found');
      
      await expect(signer.receiveMessage('invalid-session', 'encrypted-data'))
        .rejects
        .toThrow('Session not found');
    });
  });
});
