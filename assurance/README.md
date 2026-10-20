# Assurance

This directory records the assertions tangy-lib makes about itself and how CI
proves them, following the evidence-led model of signals, evidence, assertions
and decisions.

- `assertions.toml` lists each assertion with an ID, a statement, and the
  minimum number of passing tests (`min_evidence`) needed to support it.
  Optional `required_reports = ["linux", "windows"]` requires that minimum
  independently within each named report; evidence cannot be pooled to meet
  a platform requirement.
- Tests claim the assertions they support with a doc comment directly above
  `#[test]`:

  ```rust
  /// Assures: KEY-LOAD-001, KEY-STORE-001
  #[test]
  fn invalid_existing_stores_fail_without_changing_files() { ... }
  ```

- Python unittest methods in `scripts/test-*.py` use `# Assures: ID` directly
  above the method or its decorators. The installer tests produce JUnit with
  `scripts/run-python-tests.py`.
- CI collects Rust nextest reports and the Python installer report.
  `scripts/check-assurance.py` joins the tags to those reports.

## What the check enforces

The `assurance` CI job fails when:

- an assertion has fewer passing tagged tests than `min_evidence`;
- a required report is missing or does not independently meet the minimum;
- a tagged test failed, was skipped, or is missing from every report;
- a tag names an assertion that is not in the registry; or
- a tag is not attached to a Rust `#[test]` function or Python unittest method.

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
gh attestation verify evidence.json --repo rustfoo/tangy-lib
```

## Running locally

```sh
bash scripts/check-assurance-local.sh /path/to/windows-junit.xml
```

This runs Linux tests, installer safety tests, fixture verification and both real Clevis tests, then
checks them alongside an authentic Windows nextest JUnit report from the same
revision. Download `junit-windows` from CI or produce it on Windows with
`cargo nextest run --locked --profile ci`. It writes `target/evidence.json` and
needs `cargo-nextest`, `clevis`, `jose` and Python 3.11 or later. Run as a normal
user: the installer tests check Unix ownership and unreadable directories.
Linux evidence is mandatory for `KEY-PERM-001` and `KEY-PERM-ROLLBACK-001`;
Windows evidence is mandatory for `KEY-PERM-WINDOWS-001` and
both platforms are required for `KEY-PATH-001`. Windows evidence cannot be
substituted by a renamed Linux report. Full assurance cannot be claimed from
a Linux-only run. On Fedora, `scripts/install-interop-tools.sh` extracts
Clevis and JOSE into a local prefix without installing system packages.

`ADV-OPS-001` requires both the Linux protocol regression and a stock Clevis
run with extra stored key operations. `INTEROP-PREFIX-001` requires all twelve
installer tests to pass in the separate `installer` report. Produce that report with:

```sh
python3 scripts/run-python-tests.py scripts/test-prepare-interop-prefix.py --junit target/installer-junit/junit.xml
```

## Adding an assertion

Add it to `assertions.toml`, tag the tests that support it, and set
`min_evidence` to the number of tests that must pass. Choose tests that would
fail if the assertion stopped holding; a test that merely runs the code is not
evidence.

To inspect available evidence without a Windows report, run the checker directly
with Linux, interop and installer reports; it intentionally exits unsuccessfully for the
missing Windows requirements and records those gaps. The evidence record includes
`passing_by_report` for assertions with platform requirements. The checker counts
reported tests, not their target platform metadata, so report labels must accurately
identify the original CI job.

Run `python3 scripts/test-check-assurance.py` to verify per-report minimums,
missing reports, Python JUnit generation, and failure/skip handling without external tooling.
