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

> **Release note — v0.8.0 (staged, pending publish).** Part of the coordinated
> 2026-07 correctness pass across the Nostr library family. This release makes
> seed-phrase derivation NIP-06 compliant (BIP-32 `m/44'/1237'/0'/0/0`) and public
> keys 32-byte x-only per BIP-340, verified against a shared known-answer vector set
> (including the official NIP-06 spec vectors). Both are **breaking** — see
> [CHANGELOG.md](CHANGELOG.md). The family dogfoods only its own libraries — no
> upstream `nostr-tools` dependency.

## Core Features

- 🌱 **Seedphrase Management**
  - Generate and validate BIP39 seed phrases
  - Convert between seed phrases and Nostr keys — **standard NIP-06
    derivation (BIP-32 path `m/44'/1237'/0'/0/0`)**, interoperable with
    Alby, nos2x, nak, and other NIP-06 tooling
  - Secure entropy generation
  - Multiple language support

- 🔑 **Key Operations**
  - Convert between formats (hex, nsec, npub)
  - Validate key pairs
  - Generate new key pairs
  - Public key derivation — **32-byte x-only keys per BIP-340** (Nostr identity)

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
  privateKey: keyPair.privateKey, // 32-byte private key (hex)
  publicKey: keyPair.publicKey,   // 32-byte x-only public key (hex, BIP-340)
  nsec: keyPair.nsec,            // bech32 format
  npub: keyPair.npub             // bech32 format
});
```

> **Public keys are 32-byte x-only keys (BIP-340), as required by Nostr.**
> `getPublicKey`, `seedPhraseToKeyPair`, `fromHex`, and `privateKeyToNpub` all
> return the 64-hex-char x-only key. If you specifically need the 33-byte SEC1
> compressed key (for ECDH / non-Nostr interop), use `getCompressedPublicKey`.
> This changed in v0.8.0 (previously 33-byte compressed) — see CHANGELOG.

> **Seed-phrase derivation is NIP-06 compliant as of v0.8.0.** The private key
> is derived via the BIP-32 path `m/44'/1237'/0'/0/0` from the BIP39 seed, so
> the same mnemonic yields the same key in Alby, nos2x, nak, and any other
> NIP-06 tool (verified against the official NIP-06 spec test vectors).
> Versions before 0.8.0 used a non-standard `sha256(entropy)` derivation; if
> you created an identity with an older version, recover it with
> `seedPhraseToPrivateKeyLegacy` / `seedPhraseToKeyPairLegacy`:
>
> ```typescript
> import { seedPhraseToKeyPairLegacy } from 'nostr-nsec-seedphrase';
> const oldIdentity = seedPhraseToKeyPairLegacy('your pre-0.8.0 seed phrase');
> ```

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

### Dependency Vulnerability Status

We actively monitor and address security vulnerabilities in this codebase. **`npm audit --omit=dev` reports zero vulnerabilities** for this package — there are no known security issues in production dependencies.

Any remaining `npm audit` findings are in development-only tooling (eslint, typescript-eslint, vitest, typedoc, etc.) and stem from transitive dependencies with no upstream fix available. These are devDependencies that are never included in the published package and pose no risk to consumers of this library. We monitor upstream fixes and update promptly when they become available.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
