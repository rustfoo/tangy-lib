#!/usr/bin/env bash
# Run the same evidence pipeline as the CI assurance job: the main suite, the
# JOSE fixture check and the Clevis interop test, then check every assertion.
# Requires cargo-nextest, plus clevis and jose on PATH (on Fedora without
# installing system packages: scripts/install-interop-tools.sh, then source its env.sh).
set -euo pipefail

cd "$(dirname "$0")/.."
for tool in cargo-nextest clevis jose python3; do
    if ! command -v "$tool" >/dev/null; then
        echo "Missing prerequisite: $tool" >&2
        exit 1
    fi
done

reports=$(mktemp -d)
trap 'rm -rf "$reports"' EXIT

cargo nextest run --locked --profile ci
cp target/nextest/ci/junit.xml "$reports/linux.xml"
python3 scripts/check-fixtures.py
cargo nextest run --locked --profile ci --features interop --test clevis
cp target/nextest/ci/junit.xml "$reports/interop.xml"

python3 scripts/check-assurance.py \
    --junit linux="$reports/linux.xml" \
    --junit interop="$reports/interop.xml" \
    --out target/evidence.json
