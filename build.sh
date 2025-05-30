#!/bin/bash
set -euo pipefail

docker buildx build --platform=linux/amd64 --build-arg SOURCE_DATE_EPOCH=1747699200 -t quex-base:latest .
