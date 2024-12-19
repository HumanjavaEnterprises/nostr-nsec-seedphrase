import { schnorrSign } from '../crypto/signing';
import { getPublicKey } from '../crypto/keys';
import { encrypt, decrypt } from './nip44';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

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

  /**
   * Connect an application to the wallet
   * @param appPubkey - Application's public key
   * @param appMetadata - Application's metadata
   * @param requestedPermissions - List of permissions requested
   * @returns Connection response
   */
  async connect(
    appPubkey: string,
    appMetadata: WalletConnectMetadata,
    requestedPermissions: string[]
  ): Promise<WalletResponse> {
    // Store app information
    this.connectedApps.set(appPubkey, appMetadata);
    
    // Initialize permissions
    if (!this.permissions.has(appPubkey)) {
      this.permissions.set(appPubkey, new Set());
    }
    
    // Add requested permissions
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

  /**
   * Handle an incoming request from an application
   * @param appPubkey - Application's public key
   * @param request - The request to handle
   * @returns Response to the request
   */
  async handleRequest(appPubkey: string, request: WalletRequest): Promise<WalletResponse> {
    // Verify app is connected
    if (!this.connectedApps.has(appPubkey)) {
      return {
        id: request.id,
        error: {
          code: 4001,
          message: 'App not connected'
        }
      };
    }

    // Check permissions
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

  /**
   * Handle a sign event request
   * @param request - The signing request
   * @returns Signed event
   */
  private async handleSignEvent(request: WalletRequest): Promise<WalletResponse> {
    const event = request.params.event;
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
      id: request.id,
      result: {
        ...event,
        sig: signature  // schnorrSign already returns hex string
      }
    };
  }

  /**
   * Handle an encrypt request
   * @param request - The encryption request
   * @returns Encrypted data
   */
  private async handleEncrypt(request: WalletRequest): Promise<WalletResponse> {
    const { pubkey, plaintext } = request.params;
    
    const encrypted = encrypt(plaintext, this.privateKey, pubkey);
    
    return {
      id: request.id,
      result: encrypted
    };
  }

  /**
   * Handle a decrypt request
   * @param request - The decryption request
   * @returns Decrypted data
   */
  private async handleDecrypt(request: WalletRequest): Promise<WalletResponse> {
    const { pubkey, ciphertext } = request.params;
    
    const decrypted = decrypt(ciphertext, this.privateKey, pubkey);
    
    return {
      id: request.id,
      result: decrypted
    };
  }

  /**
   * Disconnect an application
   * @param appPubkey - Application's public key
   */
  disconnect(appPubkey: string): void {
    this.connectedApps.delete(appPubkey);
    this.permissions.delete(appPubkey);
  }

  /**
   * Get list of connected applications
   * @returns Map of connected applications and their metadata
   */
  getConnectedApps(): Map<string, WalletConnectMetadata> {
    return new Map(this.connectedApps);
  }

  /**
   * Get permissions for a specific application
   * @param appPubkey - Application's public key
   * @returns Set of permissions or undefined if app not connected
   */
  getAppPermissions(appPubkey: string): Set<string> | undefined {
    return this.permissions.get(appPubkey);
  }
}
