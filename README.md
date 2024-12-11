# nostr-nsec-seedphrase

A comprehensive TypeScript library for managing Nostr keys with seed phrases, including event signing, verification, and WebSocket utilities.

## Features

- Generate and manage seed phrases for Nostr keys
- Convert between different key formats (hex, nsec, npub)
- Sign and verify messages
- Create and verify Nostr events
- WebSocket utilities for Nostr applications
- TypeScript support with full type definitions

## Installation

```bash
npm install nostr-nsec-seedphrase
```

## Usage

### Key Generation and Management

```typescript
import { generateKeyPairWithSeed, seedPhraseToKeyPair } from 'nostr-nsec-seedphrase';

// Generate a new key pair with seed phrase
const keyPair = generateKeyPairWithSeed();
console.log(keyPair);
// {
//   privateKey: '...',
//   publicKey: '...',
//   nsec: '...',
//   npub: '...',
//   seedPhrase: '...'
// }

// Convert existing seed phrase to key pair
const existingKeyPair = seedPhraseToKeyPair('your twelve word seed phrase here');
```

### Message Signing and Verification

```typescript
import { signMessage, verifySignature } from 'nostr-nsec-seedphrase';

// Sign a message
const signature = await signMessage('Hello Nostr!', keyPair.privateKey);

// Verify a signature
const isValid = await verifySignature('Hello Nostr!', signature, keyPair.publicKey);
```

### Nostr Events

```typescript
import { createEvent, signEvent, verifyEvent } from 'nostr-nsec-seedphrase';

// Create and sign a new event
const event = createEvent(
  'Hello Nostr!',
  1, // kind
  keyPair.privateKey,
  [] // tags
);

// Verify an event
const isValidEvent = verifyEvent(event);
```

### WebSocket Utilities

```typescript
import { configureHMAC } from 'nostr-nsec-seedphrase';

// Configure HMAC for WebSocket connections
configureHMAC();
```

### Format Conversions

```typescript
import {
  nsecToHex,
  npubToHex,
  hexToNsec,
  hexToNpub,
  fromHex
} from 'nostr-nsec-seedphrase';

// Convert between formats
const hexPrivateKey = nsecToHex('nsec1...');
const hexPublicKey = npubToHex('npub1...');
const nsec = hexToNsec(hexPrivateKey);
const npub = hexToNpub(hexPublicKey);

// Create key pair from hex
const keyPair = fromHex(hexPrivateKey);
```

## API Reference

### Key Generation

- `generateSeedPhrase()`: Generate a new BIP39 seed phrase
- `generateKeyPairWithSeed()`: Generate a new key pair with seed phrase
- `seedPhraseToKeyPair(seedPhrase: string)`: Convert seed phrase to key pair
- `validateSeedPhrase(seedPhrase: string)`: Validate a seed phrase

### Signing and Verification

- `signMessage(message: string, privateKey: string)`: Sign a message
- `verifySignature(message: string, signature: string, publicKey: string)`: Verify a signature
- `signEvent(event: NostrEvent, privateKey: string)`: Sign a Nostr event
- `verifyEvent(event: NostrEvent)`: Verify a Nostr event signature

### Event Handling

- `createEvent(content: string, kind: number, privateKey: string, tags?: string[][])`: Create a new Nostr event

### Format Conversions

- `nsecToHex(nsec: string)`: Convert nsec to hex format
- `npubToHex(npub: string)`: Convert npub to hex format
- `hexToNsec(privateKeyHex: string)`: Convert hex to nsec format
- `hexToNpub(publicKeyHex: string)`: Convert hex to npub format
- `fromHex(privateKeyHex: string)`: Create key pair from hex private key

### WebSocket Utilities

- `configureHMAC()`: Configure secp256k1 with HMAC for WebSocket connections

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
