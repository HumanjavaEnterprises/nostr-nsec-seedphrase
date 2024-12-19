# Cross-App Authorization Example

This guide demonstrates how to implement secure cross-app authorization using nostr-nsec-seedphrase. This pattern allows users to maintain their private keys in a single trusted application while safely authorizing other applications to post on their behalf.

## Use Case: MaiQR.app and PrettyGIF.app

Imagine this scenario:
- You're using **MaiQR.app** as your main Nostr identity manager
- You want to use **PrettyGIF.app** to create and post GIFs
- You don't want to share your private key with PrettyGIF.app
- You want to approve each post from within MaiQR.app

## Implementation

### 1. Setting up MaiQR.app (Key Manager)

```typescript
import { NostrConnect } from 'nostr-nsec-seedphrase';

class MaiQRKeyManager {
  private signer: NostrConnect;

  constructor(userPrivateKey: string) {
    this.signer = new NostrConnect(userPrivateKey, {
      name: "MaiQR.app",
      url: "https://maiqr.app",
      description: "Your trusted Nostr identity manager"
    });
  }

  // Handle incoming connection requests
  async handleConnectionRequest(clientPubkey: string, metadata: any) {
    // Show user approval dialog
    const approved = await this.showApprovalDialog(metadata);
    if (!approved) {
      throw new Error("User rejected connection");
    }

    // Create session with specific permissions
    return this.signer.createSession(
      clientPubkey,
      metadata,
      ["sign_event"] // Only grant event signing
    );
  }

  // Handle signing requests
  async handleSigningRequest(sessionId: string, request: any) {
    // Verify session is valid
    const session = this.signer.getSessions().get(sessionId);
    if (!session) {
      throw new Error("Invalid session");
    }

    // Show signing approval dialog to user
    const approved = await this.showSigningDialog(session.metadata, request);
    if (!approved) {
      throw new Error("User rejected signing");
    }

    // Handle the request
    return this.signer.handleRequest(sessionId, request);
  }
}
```

### 2. Setting up PrettyGIF.app (Client App)

```typescript
import { NostrWalletConnect } from 'nostr-nsec-seedphrase';

class PrettyGIFApp {
  private wallet: NostrWalletConnect;
  private sessionId: string | null = null;

  constructor() {
    this.wallet = new NostrWalletConnect({
      name: "PrettyGIF.app",
      url: "https://prettygif.app",
      description: "Create and share awesome GIFs on Nostr"
    });
  }

  // Connect to MaiQR
  async connectToMaiQR() {
    try {
      const session = await this.wallet.connect(
        "maiqr.app", // MaiQR's connection endpoint
        ["sign_event"]
      );
      
      this.sessionId = session.id;
      return true;
    } catch (error) {
      console.error("Failed to connect to MaiQR:", error);
      return false;
    }
  }

  // Post a GIF
  async postGIF(gifUrl: string, description: string) {
    if (!this.sessionId) {
      throw new Error("Not connected to MaiQR");
    }

    // Prepare the event
    const event = {
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      content: description,
      tags: [
        ["r", gifUrl],
        ["t", "gif"]
      ]
    };

    // Request signing from MaiQR
    try {
      const signedEvent = await this.wallet.requestSignature(
        this.sessionId,
        event
      );
      
      // Publish the signed event
      return this.publishEvent(signedEvent);
    } catch (error) {
      console.error("Failed to get signature:", error);
      throw error;
    }
  }
}
```

### 3. User Flow Example

```typescript
// 1. User starts PrettyGIF.app
const prettyGIF = new PrettyGIFApp();

// 2. Instead of asking for nsec, show "Connect with MaiQR" button
await prettyGIF.connectToMaiQR();
// This opens MaiQR.app which shows approval dialog

// 3. User creates a GIF and wants to post it
await prettyGIF.postGIF(
  "https://example.com/awesome.gif",
  "Check out this cool GIF! #nostr #art"
);
// MaiQR shows approval dialog with post details
```

## Security Features

1. **Zero Key Exposure**
   - Private keys never leave MaiQR.app
   - Client apps only receive signed events

2. **Granular Permissions**
   - Specify exactly what actions are allowed
   - Permissions can be time-limited
   - Different permissions for different apps

3. **User Control**
   - Approve/reject each connection
   - Approve/reject each signing request
   - Revoke access at any time

4. **Secure Communication**
   - All messages encrypted using NIP-44
   - Session-based authentication
   - Protection against replay attacks

## Best Practices

1. **For Key Manager Apps (like MaiQR)**:
   - Always show clear approval dialogs
   - Display detailed information about requesting apps
   - Implement session timeouts
   - Provide easy access management
   - Log all authorization activities

2. **For Client Apps (like PrettyGIF)**:
   - Request minimal necessary permissions
   - Handle connection errors gracefully
   - Provide clear feedback on authorization status
   - Implement reconnection logic
   - Cache session IDs securely

## Benefits Over Traditional Approaches

1. **Better Security**
   - No need to share private keys
   - Reduced attack surface
   - Centralized key management

2. **Better User Experience**
   - Single sign-on across apps
   - Consistent authorization flow
   - Clear permission management

3. **Better Development**
   - Simplified key handling
   - Standard authorization protocol
   - Reduced liability

## Error Handling

```typescript
try {
  await prettyGIF.postGIF(gifUrl, description);
} catch (error) {
  switch (error.code) {
    case 4001: // User rejected
      showMessage("Post was not approved");
      break;
    case 4100: // No permission
      showMessage("Missing required permissions");
      break;
    case 4900: // Session expired
      await prettyGIF.connectToMaiQR(); // Reconnect
      break;
    default:
      showMessage("An error occurred");
  }
}
```

This implementation pattern enables a secure and user-friendly way to manage Nostr identities across multiple applications while maintaining strong security practices.
