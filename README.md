# nostr-nsec-seedphrase

<div align="center">

[![npm version](https://img.shields.io/npm/v/nostr-nsec-seedphrase.svg)](https://www.npmjs.com/package/nostr-nsec-seedphrase)
[![npm downloads](https://img.shields.io/npm/dm/nostr-nsec-seedphrase.svg)](https://www.npmjs.com/package/nostr-nsec-seedphrase)
[![License](https://img.shields.io/npm/l/nostr-nsec-seedphrase.svg)](https://github.com/humanjavaenterprises/nostr-nsec-seedphrase/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Test Status](https://img.shields.io/github/actions/workflow/status/humanjavaenterprises/nostr-nsec-seedphrase/ci.yml?branch=main&label=tests)](https://github.com/humanjavaenterprises/nostr-nsec-seedphrase/actions)
[![Code Style](https://img.shields.io/badge/code_style-prettier-ff69b4.svg)](https://prettier.io/)

</div>

A focused TypeScript library for Nostr key management: BIP-39 seed phrases,
standard NIP-06 key derivation, NIP-19 bech32 keys, NIP-01 event signing and
NIP-49 password-encrypted keys (`ncryptsec`). It depends only on the audited
`@noble` / `@scure` libraries plus `nostr-crypto-utils` (for NIP-49); no
`nostr-tools`.

> **v0.9.0** adds an optional NIP-06 `account` index and BIP-39 passphrase,
> strict NIP-19 length checks, a working CommonJS build and an ESM `browser`
> build. Output for existing callers of `seedPhraseToKeyPair(phrase)` is
> unchanged. See [CHANGELOG.md](CHANGELOG.md).

## Core Features

- 🌱 **Seed phrases**
  - Generate and validate BIP-39 seed phrases (English wordlist)
  - Seed phrase → Nostr keys with the **standard NIP-06 derivation**
    (BIP-32 path `m/44'/1237'/<account>'/0/0`), interoperable with Alby,
    nos2x, nak and other NIP-06 tooling
  - Optional account index and optional BIP-39 passphrase ("25th word")

- 🔑 **Keys**
  - Public keys are **32-byte x-only keys per BIP-340** (Nostr identity)
  - Convert between hex, nsec and npub; all NIP-19 helpers require exactly
    32 bytes, and nsec values must be valid secp256k1 secret keys
  - NIP-49 `ncryptsec` encryption and decryption

- 📝 **Events**
  - Create, sign and verify NIP-01 events

## NIPs Support Status

| NIP | Status | Description |
|-----|--------|-------------|
| 01 | 🟢 | Event id, signing and verification |
| 06 | 🟢 | Key derivation from a seed phrase (account index + passphrase) |
| 19 | 🟢 | Bare bech32 entities: `npub`, `nsec`, `note` (no TLV types) |
| 49 | 🟢 | Private key encryption (`ncryptsec`) |

## Installation

```bash
npm install nostr-nsec-seedphrase
```

Requires Node.js 20.19 or later (or any modern browser / Cloudflare Workers).

## Quick Start

### Generate a New Key Pair with Seed Phrase

```typescript
import { generateKeyPairWithSeed } from 'nostr-nsec-seedphrase';

const keyPair = generateKeyPairWithSeed();
// keyPair.seedPhrase, keyPair.privateKey and keyPair.nsec are secrets:
// show them to the user once, store them safely, never log them.
console.log(keyPair.npub); // public: safe to share
```

### Convert Seed Phrase to Key Pair

`seedPhraseToKeyPair` is synchronous. This example uses the public NIP-06
test-vector mnemonic; never put a real seed phrase in source code.

```typescript
import { seedPhraseToKeyPair } from 'nostr-nsec-seedphrase';

const phrase =
  'leader monkey parrot ring guide accident before fence cannon height naive bean';

const keyPair = seedPhraseToKeyPair(phrase);
keyPair.privateKey; // 32-byte private key (hex)
keyPair.publicKey;  // 32-byte x-only public key (hex, BIP-340)
keyPair.nsec;       // bech32 private key
keyPair.npub;       // bech32 public key
console.log(keyPair.npub);
// npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu
```

### Account Index and BIP-39 Passphrase (NIP-06)

Both options are optional. With no options you get account 0 and no
passphrase, the same key as every earlier version and every NIP-06 tool.

```typescript
import {
  seedPhraseToKeyPair,
  seedPhraseToPrivateKey,
  getNip06DerivationPath,
} from 'nostr-nsec-seedphrase';

const phrase =
  'leader monkey parrot ring guide accident before fence cannon height naive bean';

// Second account: m/44'/1237'/1'/0/0
const second = seedPhraseToKeyPair(phrase, { account: 1 });
console.log(getNip06DerivationPath(1)); // "m/44'/1237'/1'/0/0"
console.log(second.npub);

// BIP-39 passphrase ("25th word"): a different key from the same words
const hidden = seedPhraseToPrivateKey(phrase, { passphrase: 'extra words' });

// Both together
const both = seedPhraseToKeyPair(phrase, { account: 2, passphrase: 'extra words' });
console.log(both.npub);
```

`account` must be an integer from 0 to 2147483647. The passphrase is
NFKD-normalised as BIP-39 requires.

> **Public keys are 32-byte x-only keys (BIP-340), as required by Nostr.**
> `getPublicKey`, `seedPhraseToKeyPair`, `fromHex`, and `privateKeyToNpub` all
> return the 64-hex-char x-only key. If you specifically need the 33-byte SEC1
> compressed key (for ECDH / non-Nostr interop), use `getCompressedPublicKey`.
> This changed in v0.8.0 (previously 33-byte compressed) — see CHANGELOG.

> **Seed-phrase derivation is NIP-06 compliant as of v0.8.0** (verified
> against the official NIP-06 spec test vectors). Versions before 0.8.0 used
> a non-standard `sha256(entropy)` derivation; if you created an identity with
> an older version, recover it with `seedPhraseToPrivateKeyLegacy` /
> `seedPhraseToKeyPairLegacy`:
>
> ```typescript
> import { seedPhraseToKeyPairLegacy } from 'nostr-nsec-seedphrase';
> const oldIdentity = seedPhraseToKeyPairLegacy(
>   'leader monkey parrot ring guide accident before fence cannon height naive bean',
> );
> ```

## Key Features in Detail

### 1. Seedphrase Management

```typescript
import {
  generateSeedPhrase,
  validateSeedPhrase,
  seedPhraseToKeyPair,
} from 'nostr-nsec-seedphrase';

// Generate a new 12-word seed phrase (secret: never log it)
const seedPhrase = generateSeedPhrase();

// Validate a seed phrase (returns a boolean, writes nothing to the console)
const isValid = validateSeedPhrase(seedPhrase);

// Convert seed phrase to key pair
const keyPair = seedPhraseToKeyPair(seedPhrase);
```

### 2. Key Format Conversions

```typescript
import {
  generateKeyPairWithSeed,
  hexToNsec,
  hexToNpub,
  nsecToHex,
  npubToHex,
} from 'nostr-nsec-seedphrase';

const { privateKey: privateKeyHex, publicKey: publicKeyHex } =
  generateKeyPairWithSeed();

// Convert hex to bech32 formats
const nsec = hexToNsec(privateKeyHex);
const npub = hexToNpub(publicKeyHex);

// Convert bech32 to hex formats
const privateKeyBack = nsecToHex(nsec);
const publicKeyBack = npubToHex(npub);

// Wrong-length or out-of-range input throws:
// hexToNsec('00ff')  -> Error
```

### 3. Events

```typescript
import { generateKeyPairWithSeed, createEvent, verifyEvent } from 'nostr-nsec-seedphrase';

const { privateKey } = generateKeyPairWithSeed();
const event = await createEvent('Hello Nostr!', 1, privateKey, [['t', 'nostr']]);
console.log(await verifyEvent(event)); // true
```

### 4. Password-Encrypted Keys (NIP-49)

```typescript
import { generateKeyPairWithSeed, toNcryptsec, fromNcryptsec } from 'nostr-nsec-seedphrase';

const { privateKey } = generateKeyPairWithSeed();
const ncryptsec = toNcryptsec(privateKey, 'a strong password'); // "ncryptsec1..."
const decrypted = fromNcryptsec(ncryptsec, 'a strong password');
console.log(decrypted === privateKey); // true
```

### Key Format Utilities

```typescript
import { nip19, generateKeyPairWithSeed } from 'nostr-nsec-seedphrase';

const { privateKey: hexPrivateKey, publicKey: hexPublicKey } =
  generateKeyPairWithSeed();
const eventId = 'ab'.repeat(32);

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

## Module Support

### ESM (recommended)
```typescript
import { generateKeyPairWithSeed } from 'nostr-nsec-seedphrase';
```

### CommonJS
```javascript
const { generateKeyPairWithSeed } = require('nostr-nsec-seedphrase');
```

### Browsers, bundlers and Cloudflare Workers

Vite, webpack, esbuild and Wrangler resolve the package to its ESM build,
which runs in browsers and Workers with no Node polyfills or bundler
fallbacks.

For a plain `<script>` tag there is a standalone minified build that defines
the global `NostrNsecSeedphrase`:

```html
<script src="https://unpkg.com/nostr-nsec-seedphrase/dist/browser/nostr-nsec-seedphrase.min.js"></script>
<script>
  const keyPair = NostrNsecSeedphrase.generateKeyPairWithSeed();
  console.log(keyPair.npub);
</script>
```

## Documentation

All exports have TypeScript types and JSDoc. Generate HTML docs with
`npm run docs` and view them with `npm run docs:serve`.

## Security Considerations

- Never share, log or expose private keys or seed phrases
- Always validate input seed phrases and keys
- Key generation uses the platform CSPRNG (`crypto.getRandomValues`)
- A BIP-39 passphrase cannot be recovered: losing it loses the keys

### Dependency Vulnerability Status

`npm audit --omit=dev` reports zero vulnerabilities for the production
dependencies. Development-only tooling is never included in the published
package.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
