#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
set -eo pipefail

default_builder_image="quex213/pack:0.0.7"
default_kernel_cmdline_release="console=ttynull"
default_kernel_cmdline_debug="console=ttyS0"
default_workload_destination="initramfs"
default_output_path="ukernel.efi"
default_output_disk_path="disk.img"
default_key_request_mask="04030000c70000"

usage() {
  cat <<EOF
Usage:
  $0 [OPTIONS] SOURCE_IMAGE

Examples:
  $0 -o myuki.efi docker-daemon:myimage:mytag

  $0 --workload-destination disk -o myuki.efi --output-disk mydisk.img docker-daemon:myimage:mytag

Build a minimalist VM using SOURCE_IMAGE as the workload container.

SOURCE_IMAGE is in transport:details format.
Supported transports: dir, docker, docker-archive, docker-daemon, oci, oci-archive.
See containers-transports(5) (https://github.com/containers/image/blob/main/docs/containers-transports.5.md) for details.

Options:
  -h, --help                  display this help text
  --workload-destination MODE  where to put the workload container: initramfs | disk (default: $default_workload_destination)
                                initramfs: container is unpacked into /opt/bundle of initramfs
                                disk: container is saved as a separate .img file and mounted from /dev/vda using dm-verity
  -o, --output PATH           save resulting EFI file to PATH (default: $default_output_path)
  --output-rootfs PATH        save initramfs to PATH (default: not saved)
  --output-kernel PATH        save Linux kernel to PATH (default: not saved)
  --output-disk PATH          save workload disk image to PATH if --workload-destination disk (default: $default_output_disk_path)
  --kernel-cmdline CMD        override kernel command-line parameters (default: $default_kernel_cmdline_release or $default_kernel_cmdline_debug if --debug specified)
  --init-args INIT_ARGS       add extra arguments to init (see "Init arguments" section)
  --key-request-mask HEX      use HEX as the mask over TD Report for secret key derivation (default: $default_key_request_mask)
  --vault-mrenclave HEX       override Quex Vault enclave identity
  --builder-image IMAGE       use Docker IMAGE as UKI builder image (default: $default_builder_image)
  --debug                     use non-minimal Linux kernel build to allow debug output to the console

Init arguments:
  Init arguments are expected in the "key1=value10:value11 key2=value20:value21" format.

  Following arguments are supported:
    integrity=<device>:<name>
      Map the device to /dev/mapper/<name> with authenticated integrity control.

    crypt=<device>:<name>
      Map the device to /dev/mapper/<name> with authenticated integrity control and encryption.

    mkfs=<device>:<fstype>:<options>
      Make a filesystem on the device if there is none. Currently only ext4 is supported.
      Example: mkfs=/dev/vda:ext4:metadata_csum,64bit,extent,huge_file,dir_index

    mount=<source>:<target>:<fstype>:<flag1>,<flag2>,<flag3>,...
      Mount source to target.
      Supported flags: ro, rw, nosuid, noexec, sync, dirsync, mand, noatime, nodiratime, relatime, strictatime, lazytime.
      Example: mount=/dev/vdb:/mnt/storage:ext4:ro,noexec

License:
  Licensed under the Apache License, Version 2.0.
  You may obtain a copy of the License at:
      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the LICENSE file distributed with this project for details.
  See the NOTICE file for additional information.
EOF
}

kernel_cmdline=""
default_kernel_cmdline=$default_kernel_cmdline_release
extra_init_args=""
kernel_path="/var/linux/bzImage"
builder_image=$default_builder_image
workload_destination=$default_workload_destination
output_path=$default_output_path
output_disk_path=$default_output_disk_path
output_rootfs_path=""
output_kernel_path=""
key_request_mask=$default_key_request_mask
vault_mrenclave="231c8240fb43d8ee81a813a3a3fb05e3b9f1ae9064fe4d8629cf691a58d74112"

while true; do
  case $1 in
  -h | --help)
    usage
    exit 0
    ;;
  --workload-destination)
    case "$2" in
      initramfs|disk)
        workload_destination=$2
        ;;
      *)
        echo "Invalid value for --workload-destination: $2"
        echo "Valid options are: initramfs, disk"
        exit 1
        ;;
    esac
    shift 2
    continue
    ;;
  -o | --output)
    output_path=$2
    shift 2
    continue
    ;;
  --output-disk)
    output_disk_path=$2
    shift 2
    continue
    ;;
  --output-rootfs)
    output_rootfs_path=$2
    shift 2
    continue
    ;;
  --output-kernel)
    output_kernel_path=$2
    shift 2
    continue
    ;;
  --kernel-cmdline)
    kernel_cmdline=$2
    shift 2
    continue
    ;;
  --init-args)
    extra_init_args=$2
    shift 2
    continue
    ;;
  --key-request-mask)
    key_request_mask=$2
    shift 2
    continue
    ;;
  --vault-mrenclave)
    vault_mrenclave=$2
    shift 2
    continue
    ;;
  --builder-image)
    builder_image=$2
    shift 2
    continue
    ;;
  --debug)
    kernel_path="/var/linux/debug.bzImage"
    default_kernel_cmdline=$default_kernel_cmdline_release_debug
    shift
    continue
    ;;
  --)
    shift
    break
    ;;
  -*)
    echo "unknown option: $1"
    usage
    exit 1
    ;;
  *)
    break
    ;;
  esac
done

if [ "$#" -ne 1 ]; then
  usage
  exit 1
fi

set -u

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed or not in PATH."
  exit 1
fi

source_image=$1

tmp_in="$(mktemp -d ".in.XXXXXX")"
tmp_out="$(mktemp -d ".out.XXXXXX")"
trap 'rm -rf "$tmp_in"; rm -rf "$tmp_out"' EXIT

in_dir=$tmp_in

case $source_image in
dir:*)
  in_dir="${source_image#dir:}"
  source_image=dir:/mnt/in
  ;;
docker:*) ;;
docker-archive:*)
  source_image_details="${source_image#docker-archive:}"
  if [[ "$source_image_details" == *":"* ]]; then
    source_image_archive_path="${source_image_details%%:*}"
  else
    source_image_archive_path="$source_image_details"
  fi
  cp "$source_image_archive_path" "$in_dir/image.tar"
  source_image=docker-archive:/mnt/in/image.tar
  ;;
docker-daemon:*)
  docker save "${source_image#docker-daemon:}" -o "${tmp_in}/image.tar"
  source_image=docker-archive:/mnt/in/image.tar
  ;;
oci:*)
  source_image_details="${source_image#oci:}"
  if [[ "$source_image_details" == *":"* ]]; then
    in_dir="${source_image_details%%:*}"
    source_image="oci:/mnt/in:${source_image_details#*:}"
  else
    in_dir=$source_image_details
    source_image="oci:/mnt/in"
  fi
  ;;
oci-archive:*)
  source_image_details="${source_image#oci-archive:}"
  if [[ "$source_image_details" == *":"* ]]; then
    source_image_archive_path="${source_image_details%%:*}"
  else
    source_image_archive_path="$source_image_details"
  fi
  cp "$source_image_archive_path" "$in_dir/image.tar"
  source_image=docker-archive:/mnt/in/image.tar
  ;;
*:*)
  echo "Unsupported transport '${source_image%%:*}'"
  exit 1
  ;;
*)
  echo "Invalid source image '$source_image'"
  echo "Expected 'transport:details'"
  exit 1
  ;;
esac

docker run --rm \
  -v "$(realpath "$in_dir")":/mnt/in \
  -v "$(realpath "$tmp_out")":/mnt/out \
  -e QUEX_KERNEL_CMDLINE="${kernel_cmdline:-$default_kernel_cmdline}" \
  -e QUEX_KERNEL_PATH="$kernel_path" \
  -e QUEX_EXTRA_INIT_ARGS="$extra_init_args" \
  -e QUEX_KEY_REQUEST_MASK="$key_request_mask" \
  -e QUEX_VAULT_MRENCLAVE="$vault_mrenclave" \
  -e QUEX_WORKLOAD_DESTINATION="$workload_destination" \
  "$builder_image" \
  "$source_image"

mv "${tmp_out}/ukernel.efi" "$output_path"
if [ "$workload_destination" == "disk" ]; then
  mv "${tmp_out}/disk.img" "$output_disk_path"
fi
if [ "$output_rootfs_path" ]; then
  mv "${tmp_out}/rootfs.cpio.gz" "$output_rootfs_path"
fi
if [ "$output_kernel_path" ]; then
  mv "${tmp_out}/bzImage" "$output_kernel_path"
fi
