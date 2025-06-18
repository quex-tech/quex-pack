#!/bin/bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 VERSION"
    exit 1
fi

version="$1"
epoch=1747699200

docker buildx build \
    --platform=linux/amd64 \
    --build-arg SOURCE_DATE_EPOCH=$epoch \
    -t "quex213/pack-uki:$version" \
    .
