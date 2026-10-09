# Tangy Lib

## Description

Tangy-lib is a library implementation of the Tang server, written in rust.

The Tang protocol allows clients to store secrets which can only be recovered when they have access to the Tang server. For example, the Clevis tools allows the automated decryption of LUKS partitions when the encrypted device is connected to the local network that Tang is accessible on.

See the original Tang project for a complete description: https://github.com/latchset/tang

Fraser Tweedale's 2020 Linux Conference Australia talk on "Clevis and Tang: securing your secrets at rest" is a great resource:

[![Clevis and Tang: securing your secrets at rest](https://img.youtube.com/vi/Dk6ZuydQt9I/0.jpg)](https://www.youtube.com/watch?v=Dk6ZuydQt9I)


## Installation

Installation via cargo:

``` bash
cargo add tangy-lib
```

Or directly using in the dependencies section of Cargo.toml:

``` toml
[dependencies]
tangy-lib = "0.2"
```

## Usage

Initialize `TangyLib` with a directory of key files or a vector of JSON Web Key (JWK) strings. JWK is the JSON format used to store and exchange keys:

``` rust
use std::path::Path;
use tangy_lib::{KeySource, Result, TangyLib};

fn open_directory(dir: &Path) -> Result<TangyLib> {
    TangyLib::init(KeySource::LocalDir(dir))
}

fn open_keys(keys: &Vec<&str>) -> Result<TangyLib> {
    TangyLib::init(KeySource::Vector(keys))
}
```

`LocalDir` loads files with the `.jwk` extension from an existing directory. If there are no `.jwk` entries, it generates and saves a new key set. `Vector` loads the supplied keys without writing files; an empty vector returns an error.

A key set must contain at least one signing key and one recovery key. Both use the P-521 elliptic curve and must include a private key with matching public coordinates. Each JWK identifies its role through its `alg` and `key_ops` fields:

- Signing keys use `alg: "ES512"` and must include both `sign` and `verify` in `key_ops`. They sign the server's advertisement so clients can verify it.
- Recovery keys use `alg: "ECMR"` (Elliptic Curve Message Recovery) and must include `deriveKey` in `key_ops`. They let the server participate in a client's secret recovery.

Initialization returns `tangy_lib::Error` for malformed, unreadable, or incomplete key sets, unsupported algorithms, missing key operations, and file creation or write failures. Validated signing and recovery keys are retained as typed crypto keys for subsequent operations. Existing invalid keys are not automatically replaced. Generated key files are written individually: if a write fails, files already created remain in the directory and may need repair before initialization can succeed.

The library provides two protocol responses: an advertisement containing the server's public keys and signatures, and a recovery response computed from a client's public key and the server's recovery key. Both methods return JSON strings:

``` rust
use tangy_lib::{Result, TangyLib};

fn responses(tangy: &TangyLib, kid: &str, data: &str) -> Result<(String, String)> {
    let adv = tangy.adv(None)?;
    // kid identifies the server's recovery key; data is the client's JWK JSON.
    let rec = tangy.rec(kid, data)?;
    Ok((adv, rec))
}
```

Keys are identified by a thumbprint, a hash of their public JWK fields. `adv(None)` signs the advertisement with all signing keys. `adv(Some(thumbprint))` requires that the identified key exists and permits signing, and includes its signature along with those of the other signing keys. This allows Clevis clients to verify every signing key in the advertisement. An unknown thumbprint returns `Error::KeyNotFound` with the requested ID; a key that does not permit signing returns `Error::ForbiddenOperation`.

For `rec(&kid, &data)`, `kid` is the thumbprint of a server recovery key and `data` is the client's public key encoded as a JWK string. The client key must describe a valid point on P-521. Its `alg` and `key_ops` fields are optional; if present, `alg` must be `"ECMR"` and `key_ops` must include `"deriveKey"`. Unknown keys return `Error::KeyNotFound`, unsuitable server keys return `Error::ForbiddenOperation`, and invalid client keys return `Error::InvalidRequest`.

Advertisements use JSON Web Signature (JWS) format with unpadded Base64URL fields. Neither advertisements nor recovery responses include private key material.

To generate keys for your own storage or for use with `KeySource::Vector`:

``` rust
fn generate() -> tangy_lib::Result<Vec<String>> {
    tangy_lib::create_new_key_set()
}
```

On success this returns two private JWK strings: one ES512 signing key and one ECMR recovery key. It does not write files. Generation and advertisement signing obtain an OS seed through a fallible call, then use a ChaCha20 cryptographic generator with P-521. An entropy failure returns `Error::Randomness`; a signing failure returns `Error::Signing` with the signing key ID.

All fallible public operations use the crate's `Result<T>` alias. `MyJwkEcKey::to_jwk_ec_key(public)` now returns `Result<JwkEcKey>` and validates P-521 key material, including matching public and private values for private conversion. `MyJwkEcKey::thumbprint()` returns `Result<String>`. Use `?` on these helpers and on `create_new_key_set()` when migrating from 0.1.

The public `Error` enum is non-exhaustive, so callers should include a fallback arm when matching it. `InvalidStoredKey` identifies the file path or zero-based vector index and stores its validation cause as `Box<Error>`; callers can match `source.as_ref()` directly without downcasting. `MissingKeys` identifies absent signing and recovery roles.

Operation fields use public, non-exhaustive enums rather than strings:

- `ForbiddenOperation.algorithm` uses `Algorithm::{Es512, Ecmr}` and its `operation` uses `KeyOperation::{Sign, Verify, DeriveKey}`.
- `KeyWrite.operation` uses `WriteStep::{Create, Write}`. `KeyDirectory`, `KeyRead`, and `KeyWrite` carry paths and preserve their I/O causes.
- `Randomness.operation` uses `RandomPurpose::{KeyGeneration, AdvertisementSigning}`. Randomness and signing causes are opaque `Box<dyn std::error::Error + Send + Sync>` values, so the public fields remain independent of crypto dependency versions.

For example, identify a missing permission in an invalid stored key:

```rust
use tangy_lib::{Error, KeyOperation};

fn missing_permission(error: &Error) -> Option<KeyOperation> {
    match error {
        Error::InvalidStoredKey { source, .. } => match source.as_ref() {
            Error::ForbiddenOperation { operation, .. } => Some(*operation),
            _ => None,
        },
        _ => None,
    }
}
```

Validation `reason` strings and `Serialization.context` are diagnostic text and may change; match error variants and enum fields for application logic. `Serialization` also preserves its cause. Top-level messages report context; inspect `std::error::Error::source()` to report each cause once. JSON decoding causes use `JsonError`, which reports category, line, and column and deliberately stops the source chain before Serde's raw message, because type errors can quote private input values.

## Testing

Run these commands from the repository root to execute the Rust tests, check all build targets, and check formatting:

```sh
cargo test --locked
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
```

The Rust tests check advertisement signatures, secret recovery, input validation,
and key storage, including errors while reading or writing files and reuse of
saved keys after a restart. They use committed test keys and expected responses,
so no external services or command-line cryptography tools are required.
See [tests/fixtures/README.md](tests/fixtures/README.md) for how those test values
were produced and how to reproduce them.

To check compatibility with a real Tang client on Linux, install the `clevis`,
`jose`, `python3`, and `curl` command-line tools (available as packages with those
names on Debian and Ubuntu). Clevis is the client that encrypts and recovers a
secret; JOSE provides an independent implementation of the key operations.
Then run:

```sh
python3 scripts/check-fixtures.py
cargo test --locked --features interop --test clevis
```

The Python script compares the committed test values with results from JOSE.
The Cargo command enables the optional `interop` test, which starts a temporary
HTTP server on the loopback interface using this library and asks Clevis to
encrypt and decrypt a secret through it. It exercises advertisements both with
and without a requested signing-key thumbprint. No separately running Tang server
is needed. The test fails if a required tool is missing or the client fails.

On Fedora, you can use [scripts/install-interop-tools.sh](scripts/install-interop-tools.sh)
to download and extract JOSE and Clevis under `/tmp` without installing system
packages or using `sudo`. It requires DNF with its `download` command, RPM,
`rpm2cpio`, `cpio`, Bash, coreutils (including `timeout`), curl, jq, and Python 3.
The first run needs network access. Run from the repository root:

```sh
bash scripts/install-interop-tools.sh
source /tmp/tangy-lib-interop/env.sh
python3 scripts/check-fixtures.py
cargo test --locked --features interop --test clevis
```

The default directory is `/tmp/tangy-lib-interop`; it holds package downloads,
repository caches, extracted tools, and `env.sh`. Sourcing `env.sh` puts the local
commands and shared libraries on `PATH` and `LD_LIBRARY_PATH` for the current
shell. Source it again in each new shell before running the tests. If `/tmp` has
been cleared, rerun the installer. You can choose another writable directory:

```sh
bash scripts/install-interop-tools.sh /tmp/tangy-interop
source /tmp/tangy-interop/env.sh
```

The extracted tools support the Tang tests; this setup is not a system Clevis
installation for configuring encrypted disks. Other Linux distributions can use
their normal package manager as described above.

CI runs the Rust build and tests on Linux and Windows, checks compatibility with
Rust 1.85.1 on Linux, and runs the Clevis compatibility test in a separate Linux job.

## Credits

The original authors of [Tang](https://github.com/latchset/tang) are [Latchset](https://github.com/latchset/). Tang is based on the protocol described by Nathaniel McCallum and Robert Relyea (https://marc.info/?m=144173814525805).


## License

Apache-2.0 or MIT - you decide!

## How to Contribute

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed (Apache-2.0 and MIT), without any additional terms or conditions.
