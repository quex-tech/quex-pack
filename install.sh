#!/bin/bash
set -euo pipefail

root_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

sudo cp "$root_dir/pack-uki.sh" /usr/local/bin/pack-uki
