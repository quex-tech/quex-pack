#!/bin/bash
set -euo pipefail

root_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

sudo cp "$root_dir/quex-pack.sh" /usr/local/bin/quex-pack
