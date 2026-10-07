# Changelog

## [1.0.0]

### Added

- Support for active and rotated Tang keys through `KeySource::KeySets`.
- Migration, key storage and test guides.
- Linux, Windows and Clevis tests, fuzz tests and automated assurance checks.

### Changed

- **Breaking:** Use typed errors and fallible key generation and conversion.
  See [MIGRATING.md](MIGRATING.md) for API changes.
- Require Rust 1.88 and update cryptographic dependencies.
- Validate key material, key roles and permitted operations at initialization.
- Write complete key files before publication. Restrict Unix key permissions
  and inherit Windows directory permissions.
- Hide private key values in debug output and error messages.
- Use Blacksmith CI runners and add dependency security checks.

### Fixed

- Return errors for invalid input and key storage failures instead of panicking
  or ignoring failures.
- Prevent automatic key generation for invalid or incomplete key stores.
- Use unpadded Base64URL in advertisements and retain all active key signatures
  when a signing key is selected.
- Advertise key operations and recovery key metadata compatible with Clevis.
