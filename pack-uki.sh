#!/bin/bash
set -eo pipefail

usage() {
  cat <<EOF
Usage:
  $0 [OPTIONS] SOURCE_IMAGE

Examples:
  $0 -o myuki.efi docker-daemon:myimage:mytag

  $0 --payload-destination disk -o myuki.efi --output-disk mydisk.img docker-daemon:myimage:mytag

Build a minimalist VM using SOURCE_IMAGE as the payload container.

SOURCE_IMAGE is in transport:details format.
Supported transports: dir, docker, docker-archive, docker-daemon, oci, oci-archive.
See containers-transports(5) (https://github.com/containers/image/blob/main/docs/containers-transports.5.md) for details.

Options:
  -h, --help                  display this help text
  --payload-destination MODE  where to put the payload container: initramfs | disk (default: initramfs)
                                initramfs: container is unpacked into /opt/bundle of initramfs
                                disk: container is saved as a separate .img file and mounted from /dev/vda using dm-verity
  -o, --output PATH           save resulting EFI file to PATH (default: ukernel.efi)
  --output-rootfs PATH        save initramfs to PATH (default: not saved)
  --output-kernel PATH        save Linux kernel to PATH (default: not saved)
  --kernel-cmdline CMD        override kernel command-line parameters (default: console=ttynull or console=ttyS0 if --debug specified)
  --init-args CMD             add extra arguments to init
  --key-request-mask HEX      use HEX as the mask over TD Report for secret key derivation (default: 04030000c70000)
  --vault-mrenclave HEX       override Quex Vault enclave identity
  --builder-image IMAGE       use Docker IMAGE as UKI builder image (default: quex-base:latest)
  --debug                     use non-minimal Linux kernel build to allow debug output to the console
EOF
}

kernel_cmdline=""
default_kernel_cmdline="console=ttynull"
extra_init_args=""
kernel_path="/var/linux/bzImage"
builder_image="quex213/pack-uki:latest"
payload_destination="initramfs"
output_path="ukernel.efi"
output_disk_path="disk.img"
output_rootfs_path=""
output_kernel_path=""
key_request_mask="04030000c70000"
vault_mrenclave="231c8240fb43d8ee81a813a3a3fb05e3b9f1ae9064fe4d8629cf691a58d74112"

while true; do
  case $1 in
  -h | --help)
    usage
    exit 0
    ;;
  --payload-destination)
    case "$2" in
      initramfs|disk)
        payload_destination=$2
        ;;
      *)
        echo "Invalid value for --payload-destination: $2"
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
    default_kernel_cmdline="console=ttyS0"
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
  -e QUEX_PAYLOAD_DESTINATION="$payload_destination" \
  "$builder_image" \
  "$source_image"

mv "${tmp_out}/ukernel.efi" "$output_path"
if [ "$payload_destination" == "disk" ]; then
  mv "${tmp_out}/disk.img" "$output_disk_path"
fi
if [ "$output_rootfs_path" ]; then
  mv "${tmp_out}/rootfs.cpio.gz" "$output_rootfs_path"
fi
if [ "$output_kernel_path" ]; then
  mv "${tmp_out}/bzImage" "$output_kernel_path"
fi
