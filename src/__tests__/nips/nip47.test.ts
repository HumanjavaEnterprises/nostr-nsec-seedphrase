import { describe, it, expect, beforeEach } from 'vitest';
import { generatePrivateKey, getPublicKey } from '../../crypto/keys';
import { NostrWalletConnect, WalletConnectMetadata } from '../../nips/nip47';

describe('NIP-47: Nostr Wallet Connect', () => {
  let wallet: NostrWalletConnect;
  let walletMetadata: WalletConnectMetadata;
  let appPrivateKey: string;
  let appPublicKey: string;
  let appMetadata: WalletConnectMetadata;

  beforeEach(() => {
    walletMetadata = {
      name: 'Test Wallet',
      description: 'A test wallet implementation'
    };
    
    const walletPrivateKey = generatePrivateKey();
    wallet = new NostrWalletConnect(walletPrivateKey, walletMetadata);
    
    appPrivateKey = generatePrivateKey();
    appPublicKey = getPublicKey(appPrivateKey);
    appMetadata = {
      name: 'Test App',
      url: 'https://testapp.com',
      description: 'A test application'
    };
  });

  describe('Connection Management', () => {
    it('should connect an application successfully', async () => {
      const permissions = ['get_public_key', 'sign_event'];
      
      const response = await wallet.connect(appPublicKey, appMetadata, permissions);
      
      expect(response.result).toBeDefined();
      expect(response.result.publicKey).toBeDefined();
      expect(response.result.metadata).toEqual(walletMetadata);
      
      const connectedApps = wallet.getConnectedApps();
      expect(connectedApps.get(appPublicKey)).toEqual(appMetadata);
    });

    it('should store permissions correctly', async () => {
      const permissions = ['get_public_key', 'sign_event'];
      
      await wallet.connect(appPublicKey, appMetadata, permissions);
      
      const storedPermissions = wallet.getAppPermissions(appPublicKey);
      expect(storedPermissions).toBeDefined();
      permissions.forEach(perm => {
        expect(storedPermissions?.has(perm)).toBe(true);
      });
    });

    it('should disconnect an application', async () => {
      await wallet.connect(appPublicKey, appMetadata, ['get_public_key']);
      
      wallet.disconnect(appPublicKey);
      
      expect(wallet.getConnectedApps().has(appPublicKey)).toBe(false);
      expect(wallet.getAppPermissions(appPublicKey)).toBeUndefined();
    });
  });

  describe('Request Handling', () => {
    beforeEach(async () => {
      await wallet.connect(appPublicKey, appMetadata, [
        'get_public_key',
        'sign_event',
        'encrypt',
        'decrypt'
      ]);
    });

    it('should handle get_public_key request', async () => {
      const request = {
        id: '1',
        method: 'get_public_key',
        params: {}
      };
      
      const response = await wallet.handleRequest(appPublicKey, request);
      
      expect(response.result).toBeDefined();
      expect(typeof response.result).toBe('string');
    });

    it('should handle sign_event request', async () => {
      const event = {
        pubkey: appPublicKey,
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
      
      const response = await wallet.handleRequest(appPublicKey, request);
      
      expect(response.result).toBeDefined();
      expect(response.result.sig).toBeDefined();
      expect(typeof response.result.sig).toBe('string');
    });

    it('should reject requests from disconnected apps', async () => {
      wallet.disconnect(appPublicKey);
      
      const request = {
        id: '3',
        method: 'get_public_key',
        params: {}
      };
      
      const response = await wallet.handleRequest(appPublicKey, request);
      
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe(4001);
    });

    it('should reject requests without permission', async () => {
      // Connect with limited permissions
      wallet.disconnect(appPublicKey);
      await wallet.connect(appPublicKey, appMetadata, ['get_public_key']);
      
      const request = {
        id: '4',
        method: 'sign_event',
        params: { event: {} }
      };
      
      const response = await wallet.handleRequest(appPublicKey, request);
      
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe(4100);
    });
  });

  describe('Encryption Integration', () => {
    beforeEach(async () => {
      await wallet.connect(appPublicKey, appMetadata, ['encrypt', 'decrypt']);
    });

    it('should handle encrypt request', async () => {
      const request = {
        id: '5',
        method: 'encrypt',
        params: {
          pubkey: appPublicKey,
          plaintext: 'Secret message'
        }
      };
      
      const response = await wallet.handleRequest(appPublicKey, request);
      
      expect(response.result).toBeDefined();
      expect(typeof response.result).toBe('string');
    });

    it('should handle decrypt request', async () => {
      const plaintext = 'Secret message';
      
      // First encrypt
      const encryptRequest = {
        id: '6',
        method: 'encrypt',
        params: {
          pubkey: appPublicKey,
          plaintext
        }
      };
      
      const encryptResponse = await wallet.handleRequest(appPublicKey, encryptRequest);
      
      // Then decrypt
      const decryptRequest = {
        id: '7',
        method: 'decrypt',
        params: {
          pubkey: appPublicKey,
          ciphertext: encryptResponse.result
        }
      };
      
      const decryptResponse = await wallet.handleRequest(appPublicKey, decryptRequest);
      
      expect(decryptResponse.result).toBe(plaintext);
    });
  });
});
