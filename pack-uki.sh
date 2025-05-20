#!/bin/bash
set -euo pipefail

CONTAINER_IMAGE=${CONTAINER_IMAGE:-quex-base:latest}

if [ "$#" -ne 3 ]; then
  echo "Usage: $(basename "$0") <image-ref> <kernel-cmdline> <initrd-out>" >&2
  exit 1
fi

IMAGE_REF=$1
KERNEL_CMDLINE=$2
INITRD_OUT=$3

tmp_in="$(mktemp -d ".in.XXXXXX")"
tmp_out="$(mktemp -d ".out.XXXXXX")"
trap 'rm -rf "$tmp_in"; rm -rf "$tmp_out"' EXIT

if [[ "$IMAGE_REF" == docker-daemon:* ]]; then
  docker save "${IMAGE_REF#docker-daemon:}" -o "${tmp_in}/image.tar"
  IMAGE_REF=docker-archive:/mnt/in/image.tar
fi

docker run --rm \
  -v "$(realpath "$tmp_in")":/mnt/in \
  -v "$(realpath "$tmp_out")":/mnt/out \
  -e QUEX_KERNEL_CMDLINE="$KERNEL_CMDLINE" \
  "$CONTAINER_IMAGE" \
  "$IMAGE_REF"

mv "${tmp_out}/ukernel.efi" "$INITRD_OUT"
