# Nostr Nsec Seedphrase Library

[![npm version](https://badge.fury.io/js/nostr-nsec-seedphrase.svg)](https://badge.fury.io/js/nostr-nsec-seedphrase)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-4.9.5-blue.svg)](https://www.typescriptlang.org/)
[![Node.js CI](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase-library/workflows/Node.js%20CI/badge.svg)](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase-library/actions)

A comprehensive TypeScript library for managing Nostr keys, including seedphrase generation, key conversions, and secure key management.

## Features

- Generate secure BIP39 mnemonics for Nostr key pairs
- Create nsec private keys from hex format
- Convert between nsec/npub and hex representations
- TypeScript support with comprehensive type definitions
- Secure key management utilities
- Extensive testing and documentation

## Installation

```bash
npm install nostr-nsec-seedphrase
```

## Usage

### Basic Key Generation

```typescript
import { NostrSeedPhrase } from 'nostr-nsec-seedphrase';

// Generate new keys with mnemonic
const keys = await NostrSeedPhrase.generateNew();
console.log(keys);
// {
//   mnemonic: "your twelve word mnemonic phrase here",
//   nsec: "nsec1...",
//   npub: "npub1...",
//   privateKeyHex: "hex...",
//   publicKeyHex: "hex..."
// }
```

### Converting Hex to Nsec

```typescript
const nsec = await NostrSeedPhrase.hexToNsec('your-hex-private-key');
console.log(nsec); // "nsec1..."
```

### Converting Nsec to Hex

```typescript
const hex = await NostrSeedPhrase.nsecToHex('nsec1...');
console.log(hex); // "hex..."
```

### Converting Npub to Hex

```typescript
const hex = await NostrSeedPhrase.npubToHex('npub1...');
console.log(hex); // "hex..."
```

### Converting Hex to Npub

```typescript
const npub = await NostrSeedPhrase.hexToNpub('hex...');
console.log(npub); // "npub1..."
```

## API Reference

### `generateNew()`

Generates a new Nostr key pair with mnemonic phrase.

**Returns:**
```typescript
{
  mnemonic: string;
  nsec: string;
  npub: string;
  privateKeyHex: string;
  publicKeyHex: string;
}
```

### `hexToNsec(hexPrivateKey: string)`

Converts a hex private key to nsec format.

**Parameters:**
- `hexPrivateKey`: Hex string of the private key

**Returns:** `Promise<string>` - The nsec format private key

### `nsecToHex(nsec: string)`

Converts an nsec private key to hex format.

**Parameters:**
- `nsec`: The nsec format private key

**Returns:** `Promise<string>` - The hex format private key

### `npubToHex(npub: string)`

Converts an npub public key to hex format.

**Parameters:**
- `npub`: The npub format public key

**Returns:** `Promise<string>` - The hex format public key

### `hexToNpub(hexPublicKey: string)`

Converts a hex public key to npub format.

**Parameters:**
- `hexPublicKey`: Hex string of the public key

**Returns:** `Promise<string>` - The npub format public key

## Security Best Practices

1. **Never Share Private Keys**: Keep your nsec and private key hex values secure and never share them.
2. **Backup Mnemonics**: Safely store your mnemonic phrase in a secure location.
3. **Verify Keys**: Always verify key pairs after generation or conversion.
4. **Environment Variables**: Use environment variables for storing sensitive keys in production.
5. **Memory Management**: Clear sensitive data from memory when no longer needed.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## Testing

Run the test suite:

```bash
npm test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- Create an [Issue](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/issues)
- Follow on [Nostr](https://snort.social/p/npub12xyl6w6aacmqa3gmmzwrr9m3u0ldx3dwqhczuascswvew9am9q4sfg99cx)
- Follow on [X (Twitter)](https://x.com/vveerrgg)

## Acknowledgments

- [nostr-tools](https://github.com/nbd-wtf/nostr-tools) - For Nostr protocol utilities
- [bip39](https://github.com/bitcoinjs/bip39) - For mnemonic generation
