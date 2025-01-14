# nostr-nsec-seedphrase

<div align="center">

[![npm version](https://img.shields.io/npm/v/nostr-nsec-seedphrase.svg)](https://www.npmjs.com/package/nostr-nsec-seedphrase)
[![npm downloads](https://img.shields.io/npm/dm/nostr-nsec-seedphrase.svg)](https://www.npmjs.com/package/nostr-nsec-seedphrase)
[![License](https://img.shields.io/npm/l/nostr-nsec-seedphrase.svg)](https://github.com/humanjavaenterprises/nostr-nsec-seedphrase/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Test Status](https://img.shields.io/github/actions/workflow/status/humanjavaenterprises/nostr-nsec-seedphrase/test.yml?branch=main&label=tests)](https://github.com/humanjavaenterprises/nostr-nsec-seedphrase/actions)
[![Code Style](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://prettier.io/)

</div>

A focused TypeScript library for Nostr key management and seedphrase functionality, with seamless integration with nostr-crypto-utils. This package specializes in converting between nsec keys and seed phrases, managing delegations, and handling various key formats.

## Core Features

- 🌱 **Seedphrase Management**
  - Generate and validate BIP39 seed phrases
  - Convert between seed phrases and Nostr keys
  - Secure entropy generation
  - Multiple language support

- 🔑 **Key Operations**
  - Convert between formats (hex, nsec, npub)
  - Validate key pairs
  - Generate new key pairs
  - Public key derivation

- 📝 **Delegation Support (NIP-26)**
  - Create delegation tokens
  - Time-based conditions
  - Event kind filtering
  - Token validation and verification
  - Expiry management

- 🔄 **Format Conversions**
  - Hex ↔ nsec
  - Hex ↔ npub
  - Seed phrase ↔ key pair
  - Comprehensive validation

## NIPs Support Status

🟢 Fully implemented 🟡 Partially implemented 🔴 Not implemented

| NIP | Status | Description |
|-----|--------|-------------|
| 01 | 🟢 | Basic protocol flow & event signing |
| 06 | 🟢 | Basic key derivation from seed phrase |
| 19 | 🟢 | bech32-encoded entities |
| 26 | 🟢 | Delegated event signing |

## Installation

```bash
npm install nostr-nsec-seedphrase
```

## Quick Start

### Generate a New Key Pair with Seed Phrase

```typescript
import { generateKeyPairWithSeed } from 'nostr-nsec-seedphrase';

const keyPair = generateKeyPairWithSeed();
console.log({
  seedPhrase: keyPair.seedPhrase,
  nsec: keyPair.nsec,
  npub: keyPair.npub
});
```

### Convert Seed Phrase to Key Pair

```typescript
import { seedPhraseToKeyPair } from 'nostr-nsec-seedphrase';

const keyPair = await seedPhraseToKeyPair('your twelve word seed phrase here');
console.log({
  privateKey: keyPair.privateKey, // hex format
  publicKey: keyPair.publicKey,   // hex format
  nsec: keyPair.nsec,            // bech32 format
  npub: keyPair.npub             // bech32 format
});
```

### Create and Verify Delegations

```typescript
import { createDelegation, verifyDelegation } from 'nostr-nsec-seedphrase';

// Create a delegation token
const delegation = await createDelegation(
  delegateePublicKey,
  {
    kinds: [1, 2], // allowed event kinds
    since: Math.floor(Date.now() / 1000),
    until: Math.floor(Date.now() / 1000) + 86400 // 24 hours
  },
  delegatorPrivateKey
);

// Verify a delegation
const isValid = await verifyDelegation(
  delegation,
  Math.floor(Date.now() / 1000), // current timestamp
  1 // event kind to verify
);
```

## Key Features in Detail

### 1. Seedphrase Management

The library provides comprehensive seedphrase functionality:

```typescript
import { 
  generateSeedPhrase,
  validateSeedPhrase,
  seedPhraseToKeyPair
} from 'nostr-nsec-seedphrase';

// Generate a new seed phrase
const seedPhrase = generateSeedPhrase();

// Validate an existing seed phrase
const isValid = validateSeedPhrase(seedPhrase);

// Convert seed phrase to key pair
const keyPair = await seedPhraseToKeyPair(seedPhrase);
```

### 2. Key Format Conversions

Easy conversion between different key formats:

```typescript
import {
  hexToNsec,
  hexToNpub,
  nsecToHex,
  npubToHex
} from 'nostr-nsec-seedphrase';

// Convert hex to bech32 formats
const nsec = hexToNsec(privateKeyHex);
const npub = hexToNpub(publicKeyHex);

// Convert bech32 to hex formats
const privateKeyHex = nsecToHex(nsec);
const publicKeyHex = npubToHex(npub);
```

### 3. Delegation Management

Comprehensive NIP-26 delegation support:

```typescript
import {
  createDelegation,
  verifyDelegation,
  isDelegationValid,
  getDelegationExpiry
} from 'nostr-nsec-seedphrase';

// Create a delegation with conditions
const delegation = await createDelegation(delegatee, {
  kinds: [1], // only text notes
  since: Math.floor(Date.now() / 1000),
  until: Math.floor(Date.now() / 1000) + 86400
}, delegatorPrivateKey);

// Check delegation validity
const isValid = await isDelegationValid(delegation);

// Get delegation expiry
const expiry = getDelegationExpiry(delegation);
```

## Module Support

This package supports both ESM and CommonJS usage:

### ESM (recommended)
```typescript
import { generateKeyPairWithSeed } from 'nostr-nsec-seedphrase';
```

### CommonJS
```javascript
const { generateKeyPairWithSeed } = require('nostr-nsec-seedphrase');
```

### Webpack Usage
The package is fully compatible with webpack for client-side applications. Add to your webpack config:

```javascript
module.exports = {
  resolve: {
    fallback: {
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify"),
      "buffer": require.resolve("buffer/")
    }
  }
};
```

## Documentation

The library includes comprehensive TypeScript types and JSDoc documentation. You can:

1. View the documentation in your IDE through TypeScript and JSDoc annotations
2. Generate HTML documentation using:
   ```bash
   npm run docs
   ```
3. View the generated documentation locally:
   ```bash
   npm run docs:serve
   ```
4. Access the generated documentation in the `docs` directory

### Key Format Utilities

```typescript
import { nip19 } from 'nostr-nsec-seedphrase';

// Encode/decode public keys
const npub = nip19.npubEncode(hexPublicKey);
const hexPubkey = nip19.npubDecode(npub);

// Encode/decode private keys
const nsec = nip19.nsecEncode(hexPrivateKey);
const hexPrivkey = nip19.nsecDecode(nsec);

// Encode/decode event IDs
const note = nip19.noteEncode(eventId);
const hexEventId = nip19.noteDecode(note);
```

## Integration with nostr-crypto-utils

This package is designed to work seamlessly with nostr-crypto-utils:

- Uses compatible key formats and types
- Leverages nostr-crypto-utils for cryptographic operations
- Maintains consistent error handling and validation

## Security Considerations

- Never share or expose private keys or seed phrases
- Always validate input seed phrases and keys
- Use secure entropy sources for key generation
- Implement proper key storage practices
- Regularly rotate delegation tokens
- Set appropriate expiry times for delegations

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Version 0.6.5
- Fixed TypeScript errors related to unknown type assignments across multiple files.
- Improved error handling by converting error objects to strings before logging.
- Updated logger imports to use default imports where necessary.
- Ensured consistent logging practices throughout the codebase.
- Added a checklist for future reference.
