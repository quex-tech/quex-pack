#!/bin/bash
set -eo pipefail

usage() {
  echo "Usage:"
  echo "$0 [OPTIONS] SOURCE_IMAGE"
  echo
  echo "Example:"
  echo "$0 docker-daemon:myimage:mytag -o myuki.efi"
  echo
  echo "Build a minimalist Unified kernel image using SOURCE_IMAGE as the payload container."
  echo
  echo "SOURCE_IMAGE is in transport:details format."
  echo "Supported transports: dir, docker, docker-archive, docker-daemon, oci, oci-archive."
  echo "See containers-transports(5) (https://github.com/containers/image/blob/main/docs/containers-transports.5.md) for details."
  echo
  echo "Options:"
  echo "  -h, --help               display this help text"
  echo "  -o, --output PATH        save resulting EFI file to PATH (default: ukernel.efi)"
  echo "  --output-rootfs PATH     save initramfs to PATH (default: not saved)"
  echo "  --kernel-cmdline CMD     override kernel command-line paramters (default: console=ttynull)"
  echo "  --key-request-mask HEX   use HEX as the mask over TD Report for secret key derivation (default: 04030000c70000)"
  echo "  --vault-mrenclave HEX    override Quex Vault enclave identity"
  echo "  --builder-image IMAGE    use Docker IMAGE as UKI builder image (default: quex-base:latest)"
}

kernel_cmdline=""
builder_image="quex-base:latest"
output_path="ukernel.efi"
output_rootfs_path=""
key_request_mask=""
vault_mrenclave=""

while true; do
  case $1 in
  -h | --help)
    usage
    exit 0
    ;;
  -o | --output)
    output_path=$2
    shift 2
    continue
    ;;
  --output-rootfs)
    output_rootfs_path=$2
    shift 2
    continue
    ;;
  --kernel-cmdline)
    kernel_cmdline=$2
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
  -e QUEX_KERNEL_CMDLINE="$kernel_cmdline" \
  -e QUEX_KEY_REQUEST_MASK="$key_request_mask" \
  -e QUEX_VAULT_MRENCLAVE="$vault_mrenclave" \
  "$builder_image" \
  "$source_image"

mv "${tmp_out}/ukernel.efi" "$output_path"
if [ "$output_rootfs_path" ]; then
  mv "${tmp_out}/rootfs.cpio.gz" "$output_rootfs_path"
fi
