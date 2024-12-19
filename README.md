# nostr-nsec-seedphrase

<div align="center">

[![npm version](https://img.shields.io/npm/v/nostr-nsec-seedphrase.svg)](https://www.npmjs.com/package/nostr-nsec-seedphrase)
[![npm downloads](https://img.shields.io/npm/dm/nostr-nsec-seedphrase.svg)](https://www.npmjs.com/package/nostr-nsec-seedphrase)
[![License](https://img.shields.io/npm/l/nostr-nsec-seedphrase.svg)](https://github.com/humanjavaenterprises/nostr-nsec-seedphrase/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Test Status](https://img.shields.io/github/actions/workflow/status/humanjavaenterprises/nostr-nsec-seedphrase/test.yml?branch=main&label=tests)](https://github.com/humanjavaenterprises/nostr-nsec-seedphrase/actions)
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

## NIPs Support Status

🟢 Fully implemented 🟡 Partially implemented 🔴 Not implemented

| NIP | Status | Description |
|-----|--------|-------------|
| 01 | 🟢 | Basic protocol flow & event signing |
| 04 | 🟢 | Encrypted Direct Messages (Legacy) |
| 05 | 🟢 | DNS-based Names and Verification |
| 06 | 🟢 | Basic key derivation from seed phrases |
| 07 | 🟢 | `window.nostr` capability for browsers |
| 13 | 🟢 | Proof of Work |
| 19 | 🟢 | bech32-encoded entities |
| 26 | 🟢 | Delegated Event Signing |
| 39 | 🟢 | External Identities in Profiles |
| 44 | 🟢 | Encrypted Direct Messages v2 |
| 46 | 🟢 | Nostr Connect (Remote Signing) |
| 47 | 🟢 | Nostr Wallet Connect |
| 49 | 🟢 | Private Key Encryption |

### Key Management Features

This library provides comprehensive support for Nostr key management through multiple NIPs:

1. **Core Key Operations**
   - Seed phrase generation and management (NIP-06)
   - Key format conversion (NIP-19)
   - Private key encryption (NIP-49)

2. **Secure Communication**
   - Modern encrypted messaging (NIP-44)
   - Legacy encryption support (NIP-04)

3. **Advanced Key Management**
   - Delegated signing capabilities (NIP-26)
   - Remote signing support (NIP-46)
   - Wallet connectivity (NIP-47)

4. **Identity & Verification**
   - DNS-based verification (NIP-05)
   - Browser integration (NIP-07)
   - External identity support (NIP-39)

### NIP-49 Implementation Details

This package fully implements NIP-49, which specifies the use of BIP-39-style mnemonic seed phrases for generating private keys in the Nostr protocol. Our implementation ensures full compatibility with the NIP-49 specification while providing robust tooling for developers.

#### Key Features & Compliance

1. **Mnemonic Generation & Handling**:
   - Full BIP-39 compliance for seed phrase generation
   - Support for multiple languages and word lists
   - Secure entropy generation for new seed phrases

2. **Standardized Key Derivation**:
   - Implements the standard derivation path (m/44'/1237'/0'/0/0)
   - Ensures compatibility with other NIP-49 compliant tools and wallets
   - Supports custom derivation paths for advanced use cases

3. **Key Format & Encoding**:
   - Outputs Nostr-compatible `nsec` and `npub` keys
   - Supports conversion between different key formats
   - Maintains compatibility with existing Nostr infrastructure

4. **Security & Best Practices**:
   - Implements secure key generation and storage practices
   - Provides validation utilities for seed phrases
   - Follows cryptographic best practices for key management

#### Interoperability

This implementation ensures compatibility with:
- Nostr wallets implementing NIP-49
- Key management tools using BIP-39 mnemonics
- Other Nostr clients and libraries following the specification

#### Validation & Testing

To verify compatibility, the package includes:
- Comprehensive test suites against NIP-49 specifications
- Validation against known test vectors
- Integration tests with common Nostr tools and libraries

## Installation

```bash
npm install nostr-nsec-seedphrase
```

## Getting Started

This library provides a comprehensive set of tools for managing Nostr keys with seed phrases. Here's how to get started:

### Prerequisites

- Node.js 16.0.0 or later
- npm or yarn package manager

### Basic Usage

#### Key Generation and Management

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

## Key Management Functions

### Public Key Generation
```typescript
import { getPublicKey } from 'nostr-nsec-seedphrase';

// Generate public key from private key
const pubkey = getPublicKey(privateKeyHex);
```

### NIP-19 Encoding/Decoding
```typescript
import { nip19 } from 'nostr-nsec-seedphrase';

// Encode/decode public keys (npub)
const npub = nip19.npubEncode(pubkeyHex);
const pubkey = nip19.npubDecode(npub);

// Encode/decode private keys (nsec)
const nsec = nip19.nsecEncode(privkeyHex);
const privkey = nip19.nsecDecode(nsec);

// Encode/decode event IDs (note)
const note = nip19.noteEncode(eventIdHex);
const eventId = nip19.noteDecode(note);
```

## API Reference

### Event Functions

#### `createEvent(content: string, kind: number, privateKey: string, tags?: string[][]): Promise<NostrEvent>`
Creates and signs a new Nostr event.
```typescript
const event = await createEvent(
  "Hello Nostr!",
  1, // kind 1 for text note
  privateKey,
  [["t", "nostr"]] // optional tags
);
```

#### `signEvent(event: UnsignedEvent, privateKey: string): Promise<string>`
Signs a Nostr event with a private key.
```typescript
const signature = await signEvent(unsignedEvent, privateKey);
```

#### `verifyEvent(event: NostrEvent): Promise<boolean>`
Verifies a Nostr event signature.
```typescript
const isValid = await verifyEvent(signedEvent);
```

### Key Management Functions

#### `seedPhraseToPrivateKey(seedPhrase: string): string`
Converts a BIP39 seed phrase to a private key.
```typescript
const privateKey = seedPhraseToPrivateKey(
  "witch collapse practice feed shame open despair creek road again ice least"
);
```

#### `privateKeyToNsec(privateKey: string): string`
Converts a private key to bech32 nsec format.
```typescript
const nsec = privateKeyToNsec(privateKey);
```

#### `privateKeyToNpub(privateKey: string): string`
Converts a private key to bech32 npub format.
```typescript
const npub = privateKeyToNpub(privateKey);
```

#### `getPublicKey(privateKey: string): string`
Derives a public key from a private key.
```typescript
const publicKey = getPublicKey(privateKey);
```

### Format Conversion Functions

#### `hexToNsec(privateKeyHex: string): string`
Converts a hex private key to bech32 nsec format.
```typescript
const nsec = hexToNsec("1234567890abcdef...");
```

#### `hexToNpub(publicKeyHex: string): string`
Converts a hex public key to bech32 npub format.
```typescript
const npub = hexToNpub("1234567890abcdef...");
```

#### `nsecToHex(nsec: string): string`
Converts a bech32 nsec private key to hex format.
```typescript
const hex = nsecToHex("nsec1...");
```

#### `npubToHex(npub: string): string`
Converts a bech32 npub public key to hex format.
```typescript
const hex = npubToHex("npub1...");
```

### Message Functions

#### `signMessage(message: string, privateKey: string): Promise<string>`
Signs a message with a private key.
```typescript
const signature = await signMessage("Hello Nostr!", privateKey);
```

#### `verifySignature(message: string, signature: string, publicKey: string): Promise<boolean>`
Verifies a message signature.
```typescript
const isValid = await verifySignature("Hello Nostr!", signature, publicKey);
```

### Utility Functions

#### `bytesToHex(bytes: Uint8Array): string`
Converts bytes to a hex string.
```typescript
const hex = bytesToHex(new Uint8Array([1, 2, 3]));
```

#### `hexToBytes(hex: string): Uint8Array`
Converts a hex string to bytes.
```typescript
const bytes = hexToBytes("010203");
```

## Error Handling

All functions include proper error handling and will throw descriptive errors when:
- Invalid input formats are provided
- Key derivation fails
- Signing or verification fails
- Conversion between formats fails

Example error handling:
```typescript
try {
  const nsec = hexToNsec(privateKeyHex);
} catch (error) {
  console.error("Failed to convert hex to nsec:", error);
}
```

## Type Definitions

The library includes comprehensive TypeScript type definitions for all functions and data structures. Key types include:

```typescript
interface UnsignedEvent {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

interface NostrEvent extends UnsignedEvent {
  id: string;
  sig: string;
}
```

## Development

### Setting Up Development Environment

1. Clone the repository
```bash
git clone https://github.com/humanjavaenterprises/nostr-nsec-seedphrase.git
cd nostr-nsec-seedphrase
```

2. Install dependencies
```bash
npm install
```

3. Build the project
```bash
npm run build
```

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage
```

### Code Style

This project uses Prettier for code formatting. Format your code before committing:

```bash
npm run format
```

## Security Considerations

- Always keep your seed phrases and private keys secure
- Never share your private keys or seed phrases
- Be cautious when using this library in a browser environment
- Consider using a hardware wallet for additional security
- Validate all inputs and handle errors appropriately

## Examples

### Cross-App Authorization

One of the most powerful features of this library is its ability to enable secure cross-app authorization. This allows users to:
- Keep their private keys in a single trusted application
- Safely authorize other apps to post on their behalf
- Maintain full control over permissions and approvals

Check out our [Cross-App Authorization Example](docs/examples/cross-app-authorization.md) to see how you can:
- Build a secure key manager application
- Implement client-side authorization requests
- Create a seamless user experience across multiple Nostr apps

This pattern is perfect for building applications like:
- Identity management apps
- Multi-app ecosystems
- Wallet applications
- Content creation tools

## Recent Updates

### v0.5.x
- 🔧 Fixed Bech32 mocking in test suite
- 🔄 Improved signature verification consistency
- 🎯 Enhanced key pair generation and validation
- 🛠️ Updated test infrastructure for better reliability
- 📦 Streamlined dependency mocking system
- ➕ Added NIP-19 encoding/decoding functions & NIP-39 support

### v0.4.0
- 📚 Added comprehensive documentation and examples
- 📝 Added Code of Conduct
- 🔍 Enhanced development setup instructions
- 🛡️ Added security considerations section

### v0.3.0
- 🔧 Enhanced module resolution for better compatibility
- ✨ Improved testing infrastructure and mocks
- 📝 Enhanced TypeScript support and configurations
- 🔒 Enhanced cryptographic functionality
- 🎯 Updated ESLint and TypeScript configurations

### v0.2.0
- 🔧 Fixed HMAC configuration for secp256k1
- ✅ Added comprehensive test coverage
- 🎯 Improved TypeScript types
- 📚 Enhanced documentation

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Before contributing:
- Read our [Code of Conduct](CODE_OF_CONDUCT.md)
- Check our [Contributing Guidelines](.github/CONTRIBUTING.md)
- Review our [Security Policy](SECURITY.md)
- Search [existing issues](https://github.com/humanjavaenterprises/nostr-nsec-seedphrase/issues) before creating a new one

## License

[MIT](LICENSE)

## Author

[Vergel Evans](https://github.com/vergelevans)

---
<div align="center">
Made with ❤️ by <a href="https://github.com/humanjavaenterprises">Humanjava Enterprises</a>
</div>
