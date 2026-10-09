# Changelog

All notable changes to this project are documented in this file.

This changelog follows the Keep a Changelog format.

## [Unreleased]

### Added

- A typed error API backed by `thiserror` 2: public non-exhaustive `Error` and
  `KeyLocation` enums, a `Result<T>` alias, and a safe `JsonError` wrapper. Errors
  distinguish invalid client requests, invalid server keys, missing keys and key
  roles, forbidden operations, directory/read/write failures, serialization,
  signing, and entropy failures, retaining causes and key IDs, paths, or
  zero-based vector indices.
- Regression coverage for typed error contracts, diagnostic redaction, and
  injected entropy, serialization, file creation, and partial-write failures.
- Public non-exhaustive `Algorithm`, `KeyOperation`, `WriteStep`, and
  `RandomPurpose` enums for matching operation fields without string comparisons;
  their `Display` implementations preserve the existing wording.
- Production unwrap/expect, panic, unreachable, indexing/slicing, and todo
  guards, with test-only allowances and strict Clippy enforcement in Linux CI.
- Error-chain regression tests that check each top-level message excludes its
  causes, and a doctest for directly matching stored-key validation causes.
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
- A Fedora helper that extracts JOSE and Clevis under `/tmp`, with activation
  and local interoperability testing instructions in the README.
- Evidence-led assurance: `assurance/assertions.toml` registers the library's
  security and correctness assertions, and tests claim them with
  `/// Assures: ID` tags. `scripts/check-assurance.py` joins the tags to nextest
  JUnit reports and fails when an assertion lacks enough passing tests, or when
  a tagged test failed, was skipped, did not run, or names an unknown assertion.
  `scripts/check-assurance-local.sh` runs the full pipeline, including Clevis,
  locally. See `assurance/README.md`.
- A CI `assurance` job that checks every assertion against the Linux and
  Clevis test reports, uploads an `evidence.json` record with the commit and
  `Cargo.lock` hash, and attests it with a signed GitHub artifact attestation
  on pushes.
- A regression test that generated key files have mode 0440 on Linux.

### Changed

- **Breaking:** `init`, `adv`, `adv_internal`, and `rec` return the crate's
  typed `Result`. `create_new_key_set`, `MyJwkEcKey::to_jwk_ec_key`, and
  `MyJwkEcKey::thumbprint` now return typed results; callers must use `?` or
  otherwise handle failures. Conversion validates P-521 public/private material.
- Initialization retains validated typed signing and recovery keys alongside
  public metadata, avoiding JSON private-key conversion during protocol calls.
- OS randomness is obtained fallibly to seed ChaCha20 before P-521 key generation
  or randomized signing. Signing uses the fallible API; entropy and signing
  failures return contextual errors instead of panicking.
- JSON decoding diagnostics expose category, line, and column through
  `JsonError`. Its `Display`, `Debug`, and source chain omit raw Serde messages
  that could quote private input values.
- **Breaking:** `InvalidStoredKey.source` is now `Box<Error>`, allowing direct
  matching of the validation cause without downcasting. `Signing.source` and
  `Randomness.source` are `Box<dyn std::error::Error + Send + Sync>`, keeping
  crypto dependency types out of public error fields.
- **Breaking:** `ForbiddenOperation.algorithm` and `.operation` use `Algorithm`
  and `KeyOperation`; `KeyWrite.operation` uses `WriteStep`; and
  `Randomness.operation` uses `RandomPurpose`. These enums replace string-based
  matching. Validation reasons and `Serialization.context` remain diagnostic
  strings whose wording is not a stable matching API.
- Signing keys are constructed from validated secret keys without serializing
  and reparsing the scalar. A direct dependency on the already-resolved `ecdsa`
  0.16.9 series enables conversion into the existing P-521 0.13 wrapper; resolved
  crypto dependency versions and the signing implementation are unchanged.
- Initialization validates stored keys as P-521 private keys with matching
  public coordinates. ES512 signing keys must permit both `sign` and `verify`;
  ECMR recovery keys must permit `deriveKey`. Unsupported algorithms and missing
  operations return errors.
- Advertisement and recovery operations enforce the selected server key's
  algorithm and allowed operations. Recovery requests may omit `alg` and
  `key_ops`, but supplied values must allow ECMR and `deriveKey`.
- CI runs on pull requests as well as pushes, uses locked dependencies for
  builds and tests, checks all targets, and checks formatting on Linux.
- Linux and Clevis CI jobs run tests with cargo-nextest using the `ci` profile
  in `.config/nextest.toml` and upload JUnit reports; doctests run separately
  with `cargo test --doc`.
- Updated locked dependency versions.
- Expanded the README with key roles, initialization and persistence behavior,
  protocol inputs and responses, the final 0.2 error API and migration guidance,
  and instructions for Rust and Clevis tests. Updated the installation example
  to the 0.2 series, and corrected JWK field documentation and initialization.
- Consolidated unknown-key and forbidden-operation variant assertions in
  `tests/errors.rs`, removing their duplication in `tests/protocol.rs` while
  retaining signature, wire-format, and recovery-vector coverage.
- Switch to Blacksmith.sh CI runners

### Fixed

- Removed production unwrap/expect calls and replaced fixed-size Base64 buffers
  with allocating encoding helpers. Removed indirect use of infallible OS
  entropy and JWK string serialization APIs.
- Stored-key messages report only the key location, so source-chain formatters
  report validation causes once. Vector locations now read `input index N`.
- Removed an unreachable missing-keys fallback in advertisement formatting.
- Recovery-result point failures are classified as invalid requests.
- Key loading propagates directory enumeration, file read, and JSON parsing
  errors instead of silently skipping invalid entries. Malformed or unreadable
  stores no longer trigger automatic key generation.
- Initialization propagates generated key file creation and write failures.
  New files use exclusive creation to avoid overwriting existing files. Writes
  remain non-transactional, so a failure can leave a partial key set.
- Invalid recovery requests and invalid keys encountered during advertisement
  or recovery return typed errors instead of panicking. Advertisement signing
  and response serialization failures also return errors.
- Advertisement JWS fields use unpadded Base64URL encoding.
- Explicit signing-key requests retain signatures from every advertised signing
  key, allowing Clevis to verify advertisements when multiple signing keys are
  present.
