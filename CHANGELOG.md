# Changelog

All notable changes to this project are documented in this file.

This changelog follows the Keep a Changelog format.

## [Unreleased]

### Added

- Public non-exhaustive `Error`, `Result<T>`, `KeyLocation`, and `JsonError`
  types. Errors distinguish invalid requests, invalid server keys, missing key
  roles, forbidden operations, persistence, serialization, signing, and entropy
  failures, retaining source chains and key IDs, paths, or vector indices.
- Regression coverage for typed error contracts, diagnostic redaction, and
  injected entropy and serialization failures. Production unwrap/expect calls
  are forbidden by scoped Clippy lints, checked in Linux CI.

### Changed

- **Breaking:** `init`, `adv`, `adv_internal`, and `rec` return the crate's
  typed `Result`. `create_new_key_set`, `MyJwkEcKey::to_jwk_ec_key`, and
  `MyJwkEcKey::thumbprint` now return typed results; callers must use `?` or
  otherwise handle failures. Conversion validates P-521 public/private material.
- Initialization retains validated typed signing and recovery keys alongside
  public metadata, avoiding JSON private-key conversion during protocol calls.
- OS randomness is obtained fallibly to seed ChaCha20 before P-521 key generation
  or randomized signing. Randomness and signing failures return errors.
- JSON decoding diagnostics retain category and position without echoing input
  values; raw Serde messages are deliberately hidden to protect private keys.

### Fixed

- Removed production unwrap/expect calls, fixed-size Base64 encoding buffers,
  and indirect use of infallible OS entropy and JWK string serialization APIs.

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
