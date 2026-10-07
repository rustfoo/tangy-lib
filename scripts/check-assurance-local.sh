#!/usr/bin/env bash
# Run the same evidence pipeline as the CI assurance job: the main suite, the
# JOSE fixture check and the Clevis interop test, then check every assertion.
# Requires cargo-nextest, plus clevis and jose on PATH (on Fedora without
# installing system packages: scripts/install-interop-tools.sh, then source its env.sh).
# Full assurance also needs an authentic Windows JUnit report from the same revision.
# Usage: bash scripts/check-assurance-local.sh /path/to/windows-junit.xml
set -euo pipefail

cd "$(dirname "$0")/.."
windows_report=${1:-}
if [[ -z "$windows_report" || ! -f "$windows_report" ]]; then
    echo "Supply a Windows nextest JUnit report from this revision as the first argument." >&2
    echo "Unix permissions require linux evidence; ACL inheritance and reparse tests require windows evidence." >&2
    exit 1
fi
for tool in cargo-nextest clevis jose python3; do
    if ! command -v "$tool" >/dev/null; then
        echo "Missing prerequisite: $tool" >&2
        exit 1
    fi
done

reports=$(mktemp -d)
trap 'rm -rf "$reports"' EXIT

python3 scripts/run-python-tests.py scripts/test-prepare-interop-prefix.py --junit "$reports/installer.xml"
cargo nextest run --locked --profile ci
cp target/nextest/ci/junit.xml "$reports/linux.xml"
python3 scripts/check-fixtures.py
cargo nextest run --locked --profile ci --features interop --test clevis
cp target/nextest/ci/junit.xml "$reports/interop.xml"

python3 scripts/check-assurance.py \
    --junit linux="$reports/linux.xml" \
    --junit interop="$reports/interop.xml" \
    --junit installer="$reports/installer.xml" \
    --junit windows="$windows_report" \
    --out target/evidence.json
