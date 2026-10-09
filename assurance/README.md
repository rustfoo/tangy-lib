# Assurance

This directory records the assertions tangy-lib makes about itself and how CI
proves them, following the evidence-led model of signals, evidence, assertions
and decisions.

- `assertions.toml` lists each assertion with an ID, a statement, and the
  minimum number of passing tests (`min_evidence`) needed to support it.
- Tests claim the assertions they support with a doc comment directly above
  `#[test]`:

  ```rust
  /// Assures: KEY-LOAD-001, KEY-STORE-001
  #[test]
  fn invalid_existing_stores_fail_without_changing_files() { ... }
  ```

- CI runs the suite with `cargo nextest run --profile ci`, which writes JUnit
  reports. `scripts/check-assurance.py` joins the tags to those reports.

## What the check enforces

The `assurance` CI job fails when:

- an assertion has fewer passing tagged tests than `min_evidence`;
- a tagged test failed, was skipped, or is missing from every report;
- a tag names an assertion that is not in the registry; or
- a tag is not attached to a `#[test]` function.

Only results from the reports count, so a tag on a test that did not run is
not evidence. The job prints tests that support no assertion, without failing.

## Evidence record

The job writes `evidence.json` with the commit, the `Cargo.lock` hash, each
assertion's supporting tests and their per-report outcomes. It uploads the
record together with the JUnit reports as the `assurance-evidence` artifact.
On pushes it also creates a signed GitHub artifact attestation, which binds
the record to the commit and workflow that produced it. Verify a downloaded
record with:

```sh
gh attestation verify evidence.json --repo martynp/tangy-lib
```

## Running locally

```sh
bash scripts/check-assurance-local.sh
```

This runs the same steps as CI, including the real Clevis test that supports
`INTEROP-001`, and writes `target/evidence.json`. It needs `cargo-nextest`,
`clevis` and `jose`. On Fedora, `scripts/install-interop-tools.sh` extracts
Clevis and JOSE into a local prefix without installing system packages.

## Adding an assertion

Add it to `assertions.toml`, tag the tests that support it, and set
`min_evidence` to the number of tests that must pass. Choose tests that would
fail if the assertion stopped holding; a test that merely runs the code is not
evidence.
