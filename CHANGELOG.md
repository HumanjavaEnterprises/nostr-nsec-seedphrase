# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
