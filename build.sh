#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 VERSION" >&2
    exit 1
fi

version=$1
epoch=$(date -d 2025-09-05 +%s)

docker buildx build \
    --platform=linux/amd64 \
    --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    -t "quex213/pack:$version" \
    .
