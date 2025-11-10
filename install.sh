#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
set -eu

root_dir=$(
    CDPATH= cd "$(dirname "$0")" || exit 1
    pwd
)

sudo cp "$root_dir/quex-pack.sh" /usr/local/bin/quex-pack
