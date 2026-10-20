# Bounded input fuzzing

The independent Cargo workspace keeps `libfuzzer-sys` and nightly tooling out of
the library's stable/MSRV dependency graph. Commit `fuzz/Cargo.lock` alongside
dependency updates. The commands follow the
[cargo-fuzz guide](https://rust-fuzz.github.io/book/cargo-fuzz.html).

Install nightly Rust and cargo-fuzz, then run from the repository root:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
bash scripts/fuzz-smoke.sh
```

Each target runs for 30 seconds with AddressSanitizer, at most 4096 input bytes,
a five-second per-input timeout, and a 1024 MiB RSS limit. CI also sets a job
timeout. `recovery_request` uses a cached fixture-backed server to fuzz the
actual `rec` parser and point recovery, checking error classification and public
responses. `jwk_conversion` exercises JSON deserialization, typed public/private
conversion, public projection and thumbprints. It also creates JWKs with mutated
encoded coordinates/scalars so invalid JSON cannot dominate conversion coverage.

`seeds/` holds immutable starting inputs derived from the documented
`tests/fixtures/` keys and recovery vectors, plus malformed JSON, incorrect
metadata, scalar/coordinate length and encoding failures. These are public test
keys; never add deployment keys. Mutated corpora go in ignored `corpus/`
directories. The script fetches locked dependencies, runs offline and checks
that neither lockfile changed. Failures propagate to CI; crash/timeout inputs
and the working corpora are uploaded for reproduction.

To reproduce a saved failure, download the CI artifact and run:

```sh
cargo +nightly fuzz run recovery_request fuzz/artifacts/recovery_request/<input>
```

Use `jwk_conversion` and its artifact path for that target. A crash becomes a
normal regression test before fixing the behavior. To run longer, invoke the
target directly with a larger `-max_total_time` using the same seed directories.
These short runs supplement the protocol and validation tests; they do not
establish exhaustive coverage or replace platform assurance reports.
