# Testing and release checks

## Rust checks

Run these commands from the repository root to execute the Rust tests, check all build targets, and check formatting:

```sh
cargo test --locked
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
python3 scripts/test-check-assurance.py
python3 scripts/test-prepare-interop-prefix.py
```

To include installer safety results in assurance evidence, run
`python3 scripts/run-python-tests.py scripts/test-prepare-interop-prefix.py --junit target/installer-junit/junit.xml`.
CI and the local assurance script collect this report automatically.

The README is included in the crate documentation, so its Rust examples run as
doctests with `cargo test --locked --doc`.

The Rust tests check advertisement signatures, secret recovery, input validation,
and key storage, including errors while reading or writing files and reuse of
saved keys after a restart. They use committed test keys and expected responses,
so no external services or command-line cryptography tools are required.
See [tests/fixtures/README.md](tests/fixtures/README.md) for how those test values
were produced and how to reproduce them.

## Clevis interoperability

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

### Fedora without system installation

On Fedora, you can use [scripts/install-interop-tools.sh](scripts/install-interop-tools.sh)
to download and extract JOSE and Clevis under `/tmp` without installing system
packages or using `sudo`. It requires DNF with its `download` command, RPM,
`rpm2cpio`, `cpio`, Bash, coreutils (including `timeout`), curl, jq, and Python 3.
The first run needs network access. Run from the repository root:

```sh
bash scripts/install-interop-tools.sh
source "/tmp/tangy-lib-interop-$UID/env.sh"
python3 scripts/check-fixtures.py
cargo test --locked --features interop --test clevis
```

The default directory is `/tmp/tangy-lib-interop-$UID`; it holds package downloads,
repository caches, extracted tools, and `env.sh`. Sourcing `env.sh` puts the local
commands and shared libraries on `PATH` and `LD_LIBRARY_PATH` for the current
shell. Source it again in each new shell before running the tests. If `/tmp` has
been cleared, rerun the installer. You can choose another writable directory:

```sh
bash scripts/install-interop-tools.sh /tmp/tangy-interop
source /tmp/tangy-interop/env.sh
```

The installer creates a private prefix and checks existing ownership and write
permissions before using it. Prefix and parent-directory symlinks, unsafe shared
parents, writable contents and package links escaping the prefix are rejected.
Sticky shared parents such as `/tmp` are supported. An unsafe existing prefix
must be replaced with a new, trusted directory; the installer does not repair it.

The extracted tools support the Tang tests; this setup is not a system Clevis
installation for configuring encrypted disks. Other Linux distributions can use
their normal package manager as described above.

## Platform coverage

The minimum supported Rust version is **1.88.0**, declared as `rust-version = "1.88"`
in `Cargo.toml`. CI runs the Rust build and tests on Linux
and Windows, checks Rust 1.88.0 on Linux, and runs the Clevis compatibility tests
in a separate Linux job.

Other Unix platforms have no CI coverage. See [key storage and rotation](KEY_STORAGE.md)
for platform permission and crash-durability differences.

## Release checks and fuzzing

CI requires formatting, strict Clippy, compilation, release builds, tests and
Rust 1.88.0 checks, retaining Linux, Windows and Clevis jobs. The assurance job
checks the combined platform reports; a local Linux run alone cannot establish
Windows behavior. Repository maintainers must select these jobs as required
status checks in GitHub branch protection to enforce them before merging.

Dependency advisories are checked on pushes, pull requests and a daily schedule
with a freshly fetched RustSec database. Both the library and fuzz lockfiles are
scanned, and warnings fail the check. Dependabot monitors Cargo dependencies
(including fuzz tooling) and GitHub Actions weekly. To run the advisory checks:

```sh
cargo install cargo-audit --locked
cargo audit --deny warnings
cargo audit --file fuzz/Cargo.lock --deny warnings
```

Two bounded, seeded fuzz targets exercise recovery request parsing and JWK
conversion on pull requests, pushes and weekly runs. They run on nightly Rust
with AddressSanitizer, separately from the library's stable/MSRV builds. See
[fuzz/README.md](fuzz/README.md) for commands, resource bounds, seed provenance
and crash reproduction. A bounded run is a regression check, not exhaustive
proof of input safety.

