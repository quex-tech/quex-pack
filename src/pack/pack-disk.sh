#!/bin/bash
set -euo pipefail

src_dir=$(realpath "$1")
out_img=$(realpath "$2")
out_table=$(realpath "$3")

block_size=4096
uuid="bb1d05c4-2b82-4c5b-bea5-9063911a215f"
salt=$(printf 'veritysetup:%s' "$SOURCE_DATE_EPOCH" | sha256sum | cut -d' ' -f1)

work=/tmp/work/disk
mkdir -p $work
squash=$work/disk.squashfs

mksquashfs "$src_dir" "$squash" -quiet

data_bytes=$(stat --format=%s "$squash")
data_bytes=$((((data_bytes + block_size - 1) / block_size) * block_size))

truncate -s "$data_bytes" "$out_img"
dd if="$squash" of="$out_img" bs=$block_size conv=notrunc

data_blocks=$((data_bytes / block_size))

hash_tmp=$work/hash.tmp
hash_info=$(veritysetup --salt="$salt" \
  --data-blocks="$data_blocks" \
  --hash-offset=0 \
  --uuid $uuid \
  format "$out_img" "$hash_tmp" 2>&1)

sha256sum "$hash_tmp"
hash_size=$(stat --format=%s "$hash_tmp")

truncate -s $((data_bytes + hash_size)) "$out_img"

veritysetup --salt="$salt" \
  --data-blocks="$data_blocks" \
  --hash-offset="$data_bytes" \
  --uuid $uuid \
  format "$out_img" "$out_img" | tee "$work/verity.out"

root_hash=$(awk '/Root hash:/ {print $3}' "$work/verity.out")

veritysetup --hash-offset="$data_bytes" verify "$out_img" "$out_img" $root_hash

num_sectors=$((data_bytes / 512))

echo "0 ${num_sectors} verity 1 /dev/vda /dev/vda ${block_size} ${block_size} ${data_blocks} ${data_blocks} sha256 ${root_hash} ${salt}" > $out_table
