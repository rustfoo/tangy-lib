# Changelog

All notable changes to this project are documented in this file.

This changelog follows the Keep a Changelog format.

## [Unreleased]

## [0.2.0-alpha.1] - 2026-10-07

### Added

- Regression tests for advertisement signature verification and tampering,
  multiple signing keys, secret recovery, invalid inputs, key thumbprints,
  serialization round trips, persistence failures, and key stability after a
  restart.
- Committed test keys and independently computed recovery and thumbprint
  fixtures, with provenance documentation and a JOSE verification script.
- An optional `interop` feature and Clevis test that encrypts and decrypts
  secrets through a temporary local HTTP server, exercising default and explicit
  signing-key selection. Requires Clevis, JOSE, Python 3, and curl.
- A dedicated Linux CI job for fixture verification and Clevis interoperability.

### Changed

- Initialization validates stored keys as P-521 private keys with matching
  public coordinates. ES512 signing keys must permit both `sign` and `verify`;
  ECMR recovery keys must permit `deriveKey`. Unsupported algorithms and missing
  operations return errors.
- Advertisement and recovery operations enforce the selected server key's
  algorithm and allowed operations. Recovery requests may omit `alg` and
  `key_ops`, but supplied values must allow ECMR and `deriveKey`.
- CI runs on pull requests as well as pushes, uses locked dependencies for
  builds and tests, checks all targets, and checks formatting on Linux.
- Updated locked dependency versions.
- Expanded the README with key roles, initialization and persistence behavior,
  protocol inputs and responses, and instructions for Rust and Clevis tests.
  Corrected JWK field documentation and the initialization example.

### Fixed

- Key loading propagates directory enumeration, file read, and JSON parsing
  errors instead of silently skipping invalid entries. Malformed or unreadable
  stores no longer trigger automatic key generation.
- Initialization propagates generated key file creation and write failures.
  New files use exclusive creation to avoid overwriting existing files. Writes
  remain non-transactional, so a failure can leave a partial key set.
- Invalid recovery requests and invalid keys encountered during advertisement
  or recovery return `std::io::Error` instead of panicking. Advertisement signing
  and response serialization failures also return errors.
- Advertisement JWS fields use unpadded Base64URL encoding.
- Explicit signing-key requests retain signatures from every advertised signing
  key, allowing Clevis to verify advertisements when multiple signing keys are
  present.
