# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-07-16

### Changed
- **BREAKING: seed-phrase derivation is now NIP-06 compliant (BIP-32 path
  `m/44'/1237'/0'/0/0`).** `seedPhraseToKeyPair`, `seedPhraseToPrivateKey`,
  and `generateKeyPairWithSeed` previously derived the private key as
  `sha256(bip39-entropy)`, which is not NIP-06 and produced a different key
  than Alby, nos2x, nak, and the `nostrkey` Python SDK for the same mnemonic.
  They now reproduce the official NIP-06 spec test vectors. Keys created with
  prior versions are recoverable via `seedPhraseToPrivateKeyLegacy` /
  `seedPhraseToKeyPairLegacy`.
- **BREAKING: public keys are now 32-byte x-only per BIP-340 (were 33-byte
  compressed).** `getPublicKey`, `seedPhraseToKeyPair`, `fromHex`,
  `privateKeyToNpub`, and generated `KeyPair.publicKey`/`npub` now return the
  32-byte (64 hex char) x-only key required by Nostr. Previously they returned a
  33-byte (66 hex char) compressed key, producing non-standard npubs.
- `sign → verify` now round-trips: `verifyEvent`/`verifySignature` previously
  **threw** under real crypto because `schnorr.verify` rejects a 33-byte key.
- `validatePublicKey` now accepts only 32-byte x-only keys (previously 32 or 33).

### Added
- `seedPhraseToPrivateKeyLegacy` / `seedPhraseToKeyPairLegacy`: the old
  `sha256(bip39-entropy)` derivation, kept solely to recover identities
  created before the NIP-06 fix. Locked by a known-answer test.
- `NIP06_DERIVATION_PATH` constant (`m/44'/1237'/0'/0/0`).
- `@scure/bip32` dependency (pairs with the existing `@noble/curves` v2 /
  `@noble/hashes` v2 stack) for BIP-32 derivation.
- `getCompressedPublicKey(privateKey)` for the rare non-Nostr case that truly
  needs the 33-byte SEC1 compressed key. Deprecated for identity use.
- Shared, language-neutral known-answer vector file at
  `test/vectors/nostr-vectors.json` (BIP-340 keypairs, both official NIP-06
  spec seed-phrase vectors, legacy-derivation vector, NIP-19 round-trips,
  NIP-01 event id). Tests read from it.
- Real-crypto known-answer tests (no mocks), including a full
  `createEvent → verifyEvent` round-trip.

### Fixed
- `npub` encoders now reject non-32-byte input so a compressed key can never be
  silently encoded as an npub.
- Tests now run against REAL `@noble` crypto; removed the mocks that hid the
  compressed-vs-x-only bug.
- Added the missing `.js` extension on the internal `logger` import so the built
  ESM/CJS package resolves correctly.

## [0.7.0] - 2026-03-06

### Changed
- **Noble 2.0 migration:** `@noble/curves` ^2.0.1, `@noble/hashes` ^2.0.1
- **Vitest 4:** Upgraded test framework
- **esbuild:** Replaced webpack with esbuild for browser bundling
- **nostr-crypto-utils** dependency upgraded to ^0.6.0
- Dropped Node.js 16 support, CI runs on Node 20.x + 22.x

### Added
- NIP-49 ncryptsec support via nostr-crypto-utils v0.5.1

### Fixed
- Resolved npm audit vulnerabilities (ajv, minimatch, rollup)
- Updated test mocks for `@noble/curves/secp256k1` schnorr functions
- `configureHMAC` safety guard and proper ECDH shared secret
- Memory zeroing, Schnorr signatures, and 32-byte key derivation
- Removed private key material from all log outputs

### Security
- Eliminated elliptic HIGH vulnerability by updating nostr-crypto-utils
- Removed crypto-browserify devDep

## [0.6.6] - 2025-02-19

### Changed
- Updated dependencies to latest within major versions
- Fixed NIP-19 imports from nostr-crypto-utils

## [0.6.5] - 2025-01-13

### Changed
- Fixed TypeScript errors related to unknown type assignments across multiple files.
- Improved error handling by converting error objects to strings before logging.
- Updated logger imports to use default imports where necessary.
- Ensured consistent logging practices throughout the codebase.

### Added
- Created a CHECKLIST.md file for future development and maintenance reference.

## [0.6.4] - 2025-01-13

### Added
- Enhanced webpack compatibility for client-side usage
- Improved TypeScript type definitions
- Additional documentation for module usage patterns

## [0.6.3] - 2025-01-05

### Changed
- Updated dependency versions for better compatibility
- Improved error handling in key management functions

## [0.6.2] - 2024-12-29

### Changed
- Updated nostr-crypto-utils to version 0.4.5
- Improved NIP-19 implementation using updated nostr-crypto-utils exports
- Enhanced error messages with more detailed logging
- Streamlined type imports from nostr-crypto-utils

### Fixed
- Removed duplicate Nip19Data type definition
- Improved error handling in NIP-19 functions
- Better error messages in NIP-19 encoding/decoding functions
