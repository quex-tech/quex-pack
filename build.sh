#!/bin/bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 VERSION"
    exit 1
fi

version="$1"
epoch=$(date -d 2025-06-18 +%s)

docker buildx build \
    --platform=linux/amd64 \
    --build-arg SOURCE_DATE_EPOCH=$epoch \
    -t "quex213/pack-uki:$version" \
    .
