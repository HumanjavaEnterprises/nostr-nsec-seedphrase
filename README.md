# nostr-nsec-seedphrase

<div align="center">

[![npm version](https://img.shields.io/npm/v/nostr-nsec-seedphrase.svg)](https://www.npmjs.com/package/nostr-nsec-seedphrase)
[![npm downloads](https://img.shields.io/npm/dm/nostr-nsec-seedphrase.svg)](https://www.npmjs.com/package/nostr-nsec-seedphrase)
[![License](https://img.shields.io/npm/l/nostr-nsec-seedphrase.svg)](https://github.com/vergelevans/nostr-nsec-seedphrase/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Test Status](https://img.shields.io/github/actions/workflow/status/vergelevans/nostr-nsec-seedphrase/test.yml?branch=main&label=tests)](https://github.com/vergelevans/nostr-nsec-seedphrase/actions)
[![Code Style](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://prettier.io/)

</div>

A comprehensive TypeScript library for managing Nostr keys with seed phrases, including event signing, verification, and WebSocket utilities.

## Features

- 🔑 Generate and manage seed phrases for Nostr keys
- 🔄 Convert between different key formats (hex, nsec, npub)
- ✍️ Sign and verify messages
- 📝 Create and verify Nostr events
- 🌐 WebSocket utilities for Nostr applications
- 📦 TypeScript support with full type definitions
- ✅ Comprehensive test coverage
- 🔒 Secure key management practices

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

### Event Creation and Verification

```typescript
import { createEvent, verifyEvent } from 'nostr-nsec-seedphrase';

// Create a new event
const event = await createEvent(
  'Hello Nostr!',  // content
  1,               // kind (1 = text note)
  keyPair.privateKey,
  []               // tags (optional)
);

// Verify an event
const isValidEvent = await verifyEvent(event);
```

## Recent Updates

### v0.2.0
- 🔧 Fixed HMAC configuration for secp256k1
- ✅ Added comprehensive test coverage
- 🎯 Improved TypeScript types
- 📚 Enhanced documentation

## API Reference

### Key Management
- `generateKeyPairWithSeed()`: Generate a new key pair with seed phrase
- `seedPhraseToKeyPair(seedPhrase: string)`: Convert seed phrase to key pair
- `fromHex(privateKeyHex: string)`: Create key pair from hex private key
- `validateSeedPhrase(seedPhrase: string)`: Validate a seed phrase

### Format Conversion
- `nsecToHex(nsec: string)`: Convert nsec to hex format
- `npubToHex(npub: string)`: Convert npub to hex format
- `hexToNsec(privateKeyHex: string)`: Convert hex to nsec format
- `hexToNpub(publicKeyHex: string)`: Convert hex to npub format

### Signing and Verification
- `signMessage(message: string, privateKey: string)`: Sign a message
- `verifySignature(message: string, signature: string, publicKey: string)`: Verify a signature
- `createEvent(content: string, kind: number, privateKey: string, tags?: string[][])`: Create a Nostr event
- `verifyEvent(event: NostrEvent)`: Verify a Nostr event

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](LICENSE)

## Author

[Vergel Evans](https://github.com/vergelevans)

---
<div align="center">
Made with ❤️ by <a href="https://github.com/humanjavaenterprises">Human Java Enterprises</a>
</div>
