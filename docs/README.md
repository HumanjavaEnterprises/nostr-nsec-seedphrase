nostr-nsec-seedphrase / [Exports](modules.md)

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
| 06 | 🟢 | Basic key derivation and event signing |
| 13 | 🟢 | Proof of Work support |
| 19 | 🟢 | bech32-encoded entities |
| 49 | 🟢 | Private Key Generation from Seed Phrases |

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

## Recent Updates

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

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## License

[MIT](LICENSE)

## Author

[Vergel Evans](https://github.com/vergelevans)

---
<div align="center">
Made with ❤️ by <a href="https://github.com/humanjavaenterprises">Humanjava Enterprises</a>
</div>
