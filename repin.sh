#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# repin.sh — re-record the artifact hash pins in the Dockerfile after an
# INTENTIONAL change (kernel config, init source, snapshot/toolchain bump).
#
# Runs one LENIENT_PINS=1 harvest build (hash checks warn instead of fail),
# rewrites the ARG pins from the sha256sums printed during the build, then
# runs a strict build to verify the recorded pins are stable.
#
# The pins define the attestation trust chain — review the result with
# `git diff Dockerfile` before committing, and expect exactly the artifacts
# you meant to change (e.g. only bzImage/init/rootfs for an init patch).
#
# Usage:
#   ./repin.sh VERSION [extra build args...]
#   ./repin.sh 0.0.12
#   ./repin.sh 0.0.12 --build-arg NO_APT_SNAPSHOT=1   # snapshot outage fallback
set -eu

version=${1:?Usage: $0 VERSION [extra build args...]}
shift

epoch=$(date -d 2025-09-05 +%s)
root_dir=$(
    CDPATH= cd "$(dirname "$0")" || exit 1
    pwd
)
log=$(mktemp)
trap 'rm -f "$log"' EXIT

build() {
    if command -v docker >/dev/null 2>&1; then
        docker buildx build --progress=plain \
            --platform=linux/amd64 \
            --build-arg "SOURCE_DATE_EPOCH=$epoch" \
            "$@" "$root_dir"
    else
        podman build \
            --platform=linux/amd64 \
            --build-arg "SOURCE_DATE_EPOCH=$epoch" \
            "$@" "$root_dir"
    fi
}

echo "==> Harvest build (LENIENT_PINS=1) → quex213/pack:$version"
build --build-arg LENIENT_PINS=1 "$@" -t "quex213/pack:$version" 2>&1 | tee "$log"

# sha256sum output lines may carry a builder prefix (docker buildx plain
# progress); match the "<64 hex>  <path>" pair anywhere in the line and take
# the last occurrence.
pin() { # $1 = ARG name, $2 = path as printed by sha256sum in the Dockerfile
    hash=$(grep -oE "[0-9a-f]{64}  $2\$" "$log" | tail -1 | cut -c1-64)
    if [ -z "$hash" ]; then
        echo "ERROR: no sha256 for '$2' found in the harvest build log" >&2
        exit 1
    fi
    sed -i "s|^ARG $1=.*|ARG $1=$hash|" "$root_dir/Dockerfile"
    printf '    %-28s %s\n' "$1" "$hash"
}

echo ""
echo "==> Rewriting pins in Dockerfile"
pin LD_LINUX_SO_SHA256      "x86_64-linux-gnu/ld-linux-x86-64.so.2"
pin LIBC_SO_SHA256          "x86_64-linux-gnu/libc.so.6"
pin LINUX_BZIMAGE_SHA256    "arch/x86/boot/bzImage"
pin CRUN_BIN_SHA256         "crun"
pin E2FS_BIN_SHA256         "./misc/mke2fs.static"
pin INIT_BIN_SHA256         "init"
pin LIBDEVMAPPER_SO_SHA256  "vendor/build/usr/lib/libdevmapper.so"
pin LIBTDX_ATTEST_SO_SHA256 "vendor/build/usr/lib/x86_64-linux-gnu/libtdx_attest.so"
pin ROOTFS_CPIO_GZ_SHA256   "/var/rootfs.cpio.gz"
pin EFI_STUB_SHA256         "systemd/boot/efi/linuxx64.efi.stub"

echo ""
echo "==> Strict verification build (pins must hold)"
build "$@" -t "quex213/pack:$version"

echo ""
echo "==> Pins recorded and verified for quex213/pack:$version"
echo "    Review with: git -C $root_dir diff Dockerfile"
echo "    Only the artifacts you intentionally changed should differ."
