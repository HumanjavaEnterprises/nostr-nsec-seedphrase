# Development Checklist

## Core Architecture Principles

### 1. Cryptographic Functions
- [x] All core crypto functions must live in `/crypto`
  - [x] Key validation and generation in `keys.ts`
  - [x] Encoding/decoding utilities in `encoding.ts`
  - [ ] Signing operations in `signing.ts`
  - [ ] Encryption/decoding in `encryption.ts`
  - [x] Hashing functions in `hashing.ts`

### 2. NIP Implementation Rules
- [x] NIPs must use core crypto functions
- [x] No direct crypto implementation in NIP files
- [x] Each NIP should focus on protocol-specific logic only
- [x] Clear error handling with NIP-specific error types

### 3. Module Architecture
- [x] Use ES Module patterns consistently
- [x] No CommonJS dependencies
- [x] Clear and consistent import/export statements
- [x] Proper TypeScript types and interfaces

### 4. Testing Strategy
- [x] Mock external crypto dependencies
- [x] Test utils should use our global functions
- [x] Each NIP should have comprehensive tests
- [ ] Test both success and error cases

### 5. Package Scope and Strategy
- [ ] Package Focus
  - [ ] All new functionality must directly support nsec-seedphrase operations
  - [ ] Avoid feature creep beyond core package purpose
  - [ ] Get explicit approval before adding or removing NIPs
  - [ ] Get explicit approval before modifying core functionality
  - [ ] Keep types and interfaces focused on package requirements only

## Critical Issues
- [x] Fix HMAC initialization error in secp256k1
  - [x] Ensure `setupCrypto()` is called before any cryptographic operations
  - [x] Import and configure HMAC functions correctly
  - [x] Add test initialization module to handle crypto setup
- [x] Fix NIP-19 encoding/decoding
  - [x] Implement missing bech32 encoding functions
  - [x] Fix undefined returns in npub/nsec encoding
  - [x] Add proper validation for encoded strings
- [ ] Fix key validation and signing
  - [ ] Fix "Invalid private key" errors in encryption
  - [ ] Fix "Invalid public key" errors in key validation
  - [ ] Fix Schnorr signature implementation

## Implementation Checklist

### Phase 1: Key Management 
- [x] Implement key validation in `/crypto/keys.ts`
- [x] Fix seed phrase to key pair conversion
- [x] Add proper hex format validation
- [x] Update all NIPs to use key validation

### Phase 2: Encoding/Decoding 
- [x] Implement bech32 encoding in `/crypto/encoding.ts`
- [x] Fix NIP-19 encoding functions
- [x] Add proper error handling
- [x] Update tests to use encoding utilities

### Phase 3: Event Signing
- [ ] Move signing logic to `/crypto/signing.ts`
- [ ] Implement proper message serialization
- [ ] Fix Schnorr signature implementation
- [ ] Update NIPs to use signing utilities

### Phase 4: Encryption
- [ ] Move encryption logic to `/crypto/encryption.ts`
- [ ] Add key validation before encryption
- [ ] Fix NIP-04 implementation
- [ ] Fix NIP-44 implementation

## Test Setup and Infrastructure
- [x] Create test initialization module
  - [x] Call `setupCrypto()` in test setup
  - [x] Initialize secp256k1 with proper HMAC functions
  - [x] Set up test constants and fixtures
- [x] Add test utilities
  - [x] Key generation helpers
  - [x] Event creation helpers
  - [ ] Encryption test helpers

## Implementation Status
- [x] Create centralized error types
- [x] Implement hex conversion utilities
- [x] Fix bech32 encoding functions
- [x] Implement proper key validation
- [ ] Fix event signing and verification
- [ ] Fix encrypted direct messages
- [ ] Fix delegation signing

## Cryptographic Setup and Testing
- [x] Ensure proper secp256k1 HMAC initialization
- [x] Add randomBytes implementation for key generation
- [x] Call setupCrypto() before running any tests
- [x] Add test initialization module to handle crypto setup
- [x] Add test utilities for common test operations

## Error Handling and Types
- [x] Create centralized error types in `crypto/errors.ts`
- [x] Export and re-export errors properly
- [x] Add proper error handling to encoding functions
- [x] Add proper error handling to all NIPs
- [x] Add TypeScript type definitions for all functions

## Encoding Implementation
- [x] Fix bech32 encoding/decoding functions
- [x] Add proper validation for NIP-19 encodings
- [x] Implement hex conversion utilities
- [x] Add comprehensive encoding tests
- [x] Document encoding best practices

## Key Validation and Testing Best Practices
- [ ] Key Generation and Validation
  - [ ] Use consistent byte conversion utilities (`bytesToHex`/`hexToBytes` from `@noble/hashes/utils`)
  - [ ] Avoid mixing different hex conversion methods
  - [ ] Properly handle test constants in test environment
  - [ ] Validate keys before any cryptographic operations
  - [ ] Use compressed public keys consistently

- [ ] Test Environment Setup
  - [ ] Mock `crypto.getRandomValues` for deterministic testing
  - [ ] Return known test constants in test environment
  - [ ] Validate test keys against known good values
  - [ ] Handle both compressed and uncompressed public keys in tests
  - [ ] Test key validation with various formats (hex, bytes, invalid inputs)

- [ ] Byte Handling
  - [ ] Use consistent byte array handling across the codebase
  - [ ] Properly validate byte lengths before operations
  - [ ] Handle endianness correctly in byte conversions
  - [ ] Validate hex string formats before conversion
  - [ ] Use TypeScript types to ensure correct byte handling

- [ ] Error Cases
  - [ ] Test invalid key formats
  - [ ] Test boundary conditions for key lengths
  - [ ] Test malformed hex strings
  - [ ] Test invalid byte arrays
  - [ ] Verify error messages are descriptive and helpful

## API Version Compatibility

- [ ] Use the latest version of the secp256k1 API (utils namespace instead of etc)
  - The library has migrated from `secp256k1.etc` to `secp256k1.utils` for utility functions
  - Always use `secp256k1.utils` for functions like `hmacSha256Sync` and `hmacSha256Async`
  - Update any existing code that uses the deprecated `etc` namespace

## Documentation and Standards
- [ ] Document test setup requirements
- [ ] Document crypto initialization requirements
- [ ] Add error handling guidelines
- [ ] Document key validation rules

## Quality Checks
- [ ] All tests passing
- [x] No direct secp256k1 dependencies in NIPs
- [x] Consistent error handling
- [x] Clear documentation
- [x] Type safety throughout
