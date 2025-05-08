#!/bin/bash
set -euo pipefail

CC=x86_64-linux-gcc make -C /mnt/src CFLAGS=-DENABLE_TRACE
cp /mnt/src/init "$TARGET_DIR/init"
cp --no-dereference /mnt/src/vendor/intel/usr/lib/x86_64-linux-gnu/libtdx_attest.so* "$TARGET_DIR/lib"