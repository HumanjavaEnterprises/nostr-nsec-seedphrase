import { schnorrSign } from '../crypto/signing';
import { getPublicKey } from '../crypto/keys';
import { encrypt, decrypt } from '../crypto/encryption';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { TextEncoder } from 'util';

const utf8Encoder = new TextEncoder();

export interface WalletConnectMetadata {
  name: string;
  url?: string;
  description?: string;
  icons?: string[];
}

export interface WalletRequest {
  id: string;
  method: string;
  params: any;
}

export interface WalletResponse {
  id: string;
  result?: any;
  error?: {
    code: number;
    message: string;
  };
}

export interface SignatureRequest {
  id: string;
  pubkey: string;
  event: any;
}

export class NostrWalletConnect {
  private privateKey: string;
  private publicKey: string;
  private metadata: WalletConnectMetadata;
  private connectedApps: Map<string, WalletConnectMetadata>;
  private permissions: Map<string, Set<string>>;

  constructor(privateKey: string, metadata: WalletConnectMetadata) {
    this.privateKey = privateKey;
    this.publicKey = getPublicKey(privateKey);
    this.metadata = metadata;
    this.connectedApps = new Map();
    this.permissions = new Map();
  }

  async connect(
    appPubkey: string,
    appMetadata: WalletConnectMetadata,
    requestedPermissions: string[]
  ): Promise<WalletResponse> {
    this.connectedApps.set(appPubkey, appMetadata);
    
    if (!this.permissions.has(appPubkey)) {
      this.permissions.set(appPubkey, new Set());
    }
    
    const appPermissions = this.permissions.get(appPubkey)!;
    requestedPermissions.forEach(perm => appPermissions.add(perm));
    
    return {
      id: 'connect',
      result: {
        publicKey: this.publicKey,
        metadata: this.metadata
      }
    };
  }

  async handleRequest(appPubkey: string, request: WalletRequest): Promise<WalletResponse> {
    if (!this.connectedApps.has(appPubkey)) {
      return {
        id: request.id,
        error: {
          code: 4001,
          message: 'App not connected'
        }
      };
    }

    const appPermissions = this.permissions.get(appPubkey);
    if (!appPermissions?.has(request.method)) {
      return {
        id: request.id,
        error: {
          code: 4100,
          message: 'Permission denied'
        }
      };
    }

    try {
      switch (request.method) {
        case 'sign_event':
          return await this.handleSignEvent(request);
        case 'get_public_key':
          return {
            id: request.id,
            result: this.publicKey
          };
        case 'encrypt':
          return await this.handleEncrypt(request);
        case 'decrypt':
          return await this.handleDecrypt(request);
        default:
          return {
            id: request.id,
            error: {
              code: 4040,
              message: 'Method not found'
            }
          };
      }
    } catch (error: any) {
      return {
        id: request.id,
        error: {
          code: 5000,
          message: error.message
        }
      };
    }
  }

  private async handleSignEvent(request: WalletRequest): Promise<WalletResponse> {
    const { event } = request.params;
    
    if (!event) {
      return {
        id: request.id,
        error: {
          code: 400,
          message: 'Missing event parameter'
        }
      };
    }

    try {
      const eventData = [
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
      ];
      
      const serializedEvent = JSON.stringify(eventData);
      const eventHash = sha256(utf8Encoder.encode(serializedEvent));
      const signature = await schnorrSign(bytesToHex(eventHash), this.privateKey);
      
      return {
        id: request.id,
        result: {
          sig: signature
        }
      };
    } catch (error: any) {
      return {
        id: request.id,
        error: {
          code: 5000,
          message: error.message
        }
      };
    }
  }

  private async handleEncrypt(request: WalletRequest): Promise<WalletResponse> {
    const { pubkey, plaintext } = request.params;
    
    if (!pubkey || !plaintext) {
      return {
        id: request.id,
        error: {
          code: 400,
          message: 'Missing required parameters'
        }
      };
    }

    try {
      const ciphertext = await encrypt(plaintext, this.privateKey, pubkey);
      return {
        id: request.id,
        result: ciphertext
      };
    } catch (error: any) {
      return {
        id: request.id,
        error: {
          code: 5000,
          message: error.message
        }
      };
    }
  }

  private async handleDecrypt(request: WalletRequest): Promise<WalletResponse> {
    const { pubkey, ciphertext } = request.params;
    
    if (!pubkey || !ciphertext) {
      return {
        id: request.id,
        error: {
          code: 400,
          message: 'Missing required parameters'
        }
      };
    }

    try {
      const plaintext = await decrypt(ciphertext, this.privateKey, pubkey);
      return {
        id: request.id,
        result: plaintext
      };
    } catch (error: any) {
      return {
        id: request.id,
        error: {
          code: 5000,
          message: error.message
        }
      };
    }
  }

  disconnect(appPubkey: string): void {
    this.connectedApps.delete(appPubkey);
    this.permissions.delete(appPubkey);
  }

  getConnectedApps(): Map<string, WalletConnectMetadata> {
    return this.connectedApps;
  }

  getAppPermissions(appPubkey: string): Set<string> | undefined {
    return this.permissions.get(appPubkey);
  }
}
