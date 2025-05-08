#!/bin/bash
set -euo pipefail

mkdir -p cache output

pack-uki \
  --cache cache \
  --buildroot-output output \
  --buildroot-config buildroot.config \
  --kernel-cmdline "console=ttynull ip=10.13.192.134::10.13.192.1:255.255.192.0::eth0:off" \
  -v ./src/:/mnt/src rootfs/ base-image.efi
