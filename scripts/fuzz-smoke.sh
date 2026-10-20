#!/usr/bin/env bash
# Requires nightly Rust and cargo-fuzz. Keep seed fixtures immutable.
set -euo pipefail
cd "$(dirname "$0")/.."

fuzz_lock_hashes=$(sha256sum Cargo.lock fuzz/Cargo.lock)
# Refuse dependency drift before cargo-fuzz invokes Cargo internally.
cargo +nightly fetch --locked --manifest-path fuzz/Cargo.toml
export CARGO_NET_OFFLINE=true
for target in recovery_request jwk_conversion; do
    mkdir -p "fuzz/corpus/$target"
    cargo +nightly fuzz run "$target" "fuzz/corpus/$target" "fuzz/seeds/$target" -- \
        -max_total_time=30 -timeout=5 -max_len=4096 -rss_limit_mb=1024 \
        -verbosity=0 -print_final_stats=1
done
if [[ "$fuzz_lock_hashes" != "$(sha256sum Cargo.lock fuzz/Cargo.lock)" ]]; then
    echo "Fuzzing changed a dependency lockfile." >&2
    exit 1
fi
