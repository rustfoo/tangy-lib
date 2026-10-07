#!/usr/bin/env bash
# Extract Fedora's JOSE and Clevis packages into a local prefix without installing
# system packages. Use only for the Tang interoperability tests, not LUKS setup.
set -euo pipefail

if [[ $# -gt 1 || ${1:-} == --help ]]; then
    echo "Usage: bash scripts/install-interop-tools.sh [PREFIX]"
    echo "Default prefix: /tmp/tangy-lib-interop-$UID"
    exit 0
fi

# Keep new cache files and activation output private to this installer process.
umask 077

for tool in dnf rpm rpm2cpio cpio curl jq python3 timeout; do
    if ! command -v "$tool" >/dev/null; then
        echo "Missing prerequisite: $tool. This installer requires Fedora with DNF download support." >&2
        exit 1
    fi
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
prefix=$(python3 "$script_dir/prepare-interop-prefix.py" "${1:-/tmp/tangy-lib-interop-$UID}")
# Isolate this run from cached RPMs, and each attempt from partial downloads.
package_staging=$(mktemp -d "$prefix/packages/run.XXXXXXXX")
trap 'rm -rf -- "$package_staging"' EXIT
package_dir="$package_staging/primary"
mkdir "$package_dir"
arch=$(rpm --eval '%{_arch}')
dnf_options=(
    --setopt="cachedir=$prefix/cache"
    --setopt="system_cachedir=$prefix/cache"
    --setopt="persistdir=$prefix/state"
    --setopt="logdir=$prefix/log"
    --setopt=optional_metadata_types=
    --setopt=zchunk=False
    --setopt=timeout=15
    --setopt=retries=1
)
if ! timeout 45 dnf "${dnf_options[@]}" --repo=fedora --repo=updates \
    download --arch="$arch" --destdir="$package_dir" jose libjose clevis; then
    # Older Fedora releases move to the official archive. Retry there instead
    # of depending on the archived release's remaining third-party mirrors.
    release=$(rpm --eval '%fedora')
    archive=https://archives.fedoraproject.org/pub/archive/fedora/linux
    package_dir="$package_staging/archive"
    mkdir "$package_dir"
    timeout 180 dnf "${dnf_options[@]}" \
        --repofrompath="tangy-fedora-archive,$archive/releases/$release/Everything/$arch/os/" \
        --repofrompath="tangy-updates-archive,$archive/updates/$release/Everything/$arch/" \
        --repo=tangy-fedora-archive --repo=tangy-updates-archive \
        download --arch="$arch" --destdir="$package_dir" jose libjose clevis
fi

for package in "$package_dir"/*.rpm; do
    [[ $package == *."$arch".rpm || $package == *.noarch.rpm ]] || continue
    rpm --checksig "$package"
    (cd "$prefix/root" && rpm2cpio "$package" | cpio --extract --make-directories --unconditional --quiet)
done

# Validate extracted entries before writing or sourcing the activation file.
python3 "$script_dir/prepare-interop-prefix.py" "$prefix" >/dev/null

# Keep both command dispatch and the extracted shared libraries local.
{
    printf 'export PATH=%q:"$PATH"\n' "$prefix/root/usr/bin:$prefix/root/usr/libexec"
    printf 'export LD_LIBRARY_PATH=%q${LD_LIBRARY_PATH:+:"$LD_LIBRARY_PATH"}\n' \
        "$prefix/root/usr/lib64:$prefix/root/usr/lib"
} > "$prefix/env.sh"

# shellcheck disable=SC1091
source "$prefix/env.sh"
jose jwk gen -i '{"alg":"ES512"}' -o /dev/null
clevis encrypt tang --summary
printf '\nTools extracted. Activate them with:\n  source %q\n' "$prefix/env.sh"
