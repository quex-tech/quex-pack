#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# gcp-build-image.sh: pack a container into a UKI and import it as a Google
# Compute Engine (GCE) image that boots inside a TDX Confidential VM.
#
# Pipeline:
#   SOURCE_IMAGE -> quex-pack (initramfs mode) -> ukernel.efi
#     -> raw GPT disk with one EFI System Partition, UKI at /EFI/BOOT/BOOTX64.EFI
#     -> disk.tar.gz staged in a GCS bucket -> gcloud compute images create
#
# GCE firmware measures the UKI (Authenticode SHA-384) into RTMR[1] at boot,
# so the running TD is verifiable from the container and the quex-pack commit.
#
# Requires: quex-pack (with docker or podman), sgdisk, mkfs.fat, mtools,
# gcloud and gsutil (authenticated).
set -eu

script_dir=$(
    CDPATH= cd "$(dirname "$0")" || exit 1
    pwd
)

usage() {
    cat <<USAGE
Usage:
  $0 [OPTIONS] SOURCE_IMAGE

Example:
  $0 --image-name myvm-abc1234 --bucket my-staging-bucket docker-daemon:myimage:mytag

SOURCE_IMAGE is in transport:details format, see quex-pack --help.

Options:
  -h, --help              display this help text
  --image-name NAME       name of the resulting GCE image (required)
  --bucket BUCKET         GCS bucket for staging the disk archive (required)
  --project PROJECT       GCP project (default: gcloud config)
  --vault-mrenclave HEX   override Quex Vault enclave identity (default: quex-pack default)
  --ephemeral-key         disable vault key delivery: init generates a new random key
                          on every boot, so the TD identity is not stable (testing only)
  --kernel-cmdline CMD    extra kernel command-line parameters (ip=dhcp is always added)
  --builder-image IMAGE   use Docker IMAGE as UKI builder image (default: quex-pack default)
  -o, --output PATH       also keep the UKI at PATH
  --debug                 debug kernel with serial console on ttyS0; this changes the
                          measurement and leaks boot and workload logs to the serial port

Environment:
  QUEX_PACK               quex-pack executable (default: quex-pack from PATH, else ../quex-pack.sh)
USAGE
}

image_name=""
bucket=""
project=""
vault_mrenclave=""
ephemeral_key=""
extra_cmdline=""
builder_image=""
output=""
debug=""

while [ $# -gt 0 ]; do
    case $1 in
    -h | --help)
        usage
        exit 0
        ;;
    --image-name)
        image_name=$2
        shift 2
        ;;
    --bucket)
        bucket=$2
        shift 2
        ;;
    --project)
        project=$2
        shift 2
        ;;
    --vault-mrenclave)
        vault_mrenclave=$2
        shift 2
        ;;
    --ephemeral-key)
        ephemeral_key=1
        shift
        ;;
    --kernel-cmdline)
        extra_cmdline=$2
        shift 2
        ;;
    --builder-image)
        builder_image=$2
        shift 2
        ;;
    -o | --output)
        output=$2
        shift 2
        ;;
    --debug)
        debug=1
        shift
        ;;
    --)
        shift
        break
        ;;
    -*)
        echo "Unknown option '$1'" >&2
        usage >&2
        exit 1
        ;;
    *)
        break
        ;;
    esac
done

if [ $# -ne 1 ]; then
    usage >&2
    exit 1
fi
source_image=$1

if [ -z "$image_name" ] || [ -z "$bucket" ]; then
    echo "--image-name and --bucket are required" >&2
    exit 1
fi
if [ -n "$ephemeral_key" ] && [ -n "$vault_mrenclave" ]; then
    echo "--ephemeral-key and --vault-mrenclave are mutually exclusive" >&2
    exit 1
fi
if [ -z "$project" ]; then
    project=$(gcloud config get-value project 2>/dev/null || true)
fi
if [ -z "$project" ]; then
    echo "No GCP project: pass --project or run 'gcloud config set project'" >&2
    exit 1
fi

for tool in sgdisk mkfs.fat mmd mcopy gcloud gsutil sha256sum sha384sum; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing tool: $tool" >&2
        exit 1
    fi
done

quex_pack=${QUEX_PACK:-}
if [ -z "$quex_pack" ]; then
    if command -v quex-pack >/dev/null 2>&1; then
        quex_pack=quex-pack
    elif [ -x "$script_dir/../quex-pack.sh" ]; then
        quex_pack=$script_dir/../quex-pack.sh
    else
        echo "quex-pack not found: run install.sh or set QUEX_PACK" >&2
        exit 1
    fi
fi

workdir=$(mktemp -d)
gcs_object="gs://$bucket/quex-pack/$image_name.tar.gz"

cleanup() {
    gsutil -q rm "$gcs_object" 2>/dev/null || true
    rm -rf "$workdir"
}
trap cleanup EXIT

uki=$workdir/ukernel.efi
esp=$workdir/esp.img
disk=$workdir/disk.raw

# quex-pack calls docker. On podman-only hosts, provide a docker shim.
if ! command -v docker >/dev/null 2>&1; then
    if ! command -v podman >/dev/null 2>&1; then
        echo "Neither docker nor podman found" >&2
        exit 1
    fi
    mkdir -p "$workdir/bin"
    printf '#!/bin/sh\nexec podman "$@"\n' >"$workdir/bin/docker"
    chmod +x "$workdir/bin/docker"
    PATH=$workdir/bin:$PATH
    export PATH
fi

# Step 1: pack the container into a single UKI.
#
# GCE boots one disk through UEFI, so the workload goes into the initramfs.
# GCE C3 networking is gVNIC with DHCP, hence ip=dhcp. The release kernel has
# no UART driver, so console output needs --debug together with console=ttyS0.
if [ -n "$debug" ]; then
    cmdline="earlycon=uart8250,io,0x3f8,115200 console=ttyS0,115200n8 ip=dhcp"
else
    cmdline="console=ttynull ip=dhcp"
fi
if [ -n "$extra_cmdline" ]; then
    cmdline="$cmdline $extra_cmdline"
fi

set -- --workload-destination initramfs --kernel-cmdline "$cmdline" -o "$uki"
if [ -n "$ephemeral_key" ]; then
    set -- "$@" --vault-mrenclave ""
fi
if [ -n "$vault_mrenclave" ]; then
    set -- "$@" --vault-mrenclave "$vault_mrenclave"
fi
if [ -n "$builder_image" ]; then
    set -- "$@" --builder-image "$builder_image"
fi
if [ -n "$debug" ]; then
    set -- "$@" --debug
fi

echo "==> Running quex-pack"
"$quex_pack" "$@" "$source_image"

uki_sha256=$(sha256sum "$uki" | cut -c1-64)
uki_sha384=$(sha384sum "$uki" | cut -c1-96)
if [ -n "$output" ]; then
    cp "$uki" "$output"
fi

# Step 2: build a GCE-importable raw disk.
#
# GPT with a single 512 MiB EFI System Partition at 1 MiB; the rest of the
# 10 GiB (GCE minimum) stays unpartitioned. mtools writes the FAT image, so
# no root and no loop device are needed.
echo "==> Building disk.raw"
truncate -s 10G "$disk"
sgdisk -Z "$disk" >/dev/null
sgdisk --new=1:2048:+512M --typecode=1:ef00 --change-name=1:"EFI System" "$disk" >/dev/null
truncate -s $((512 * 1024 * 1024)) "$esp"
mkfs.fat -F 32 -n EFI "$esp" >/dev/null
MTOOLS_SKIP_CHECK=1 mmd -i "$esp" ::/EFI
MTOOLS_SKIP_CHECK=1 mmd -i "$esp" ::/EFI/BOOT
MTOOLS_SKIP_CHECK=1 mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI
dd if="$esp" of="$disk" bs=512 seek=2048 conv=notrunc status=none
tar -C "$workdir" -czf "$workdir/disk.tar.gz" disk.raw

# Step 3: stage in GCS and import. The staging object is removed on exit.
echo "==> Uploading to $gcs_object"
gsutil -q cp "$workdir/disk.tar.gz" "$gcs_object"

echo "==> Creating GCE image $image_name"
gcloud compute images create "$image_name" \
    --project="$project" \
    --source-uri="$gcs_object" \
    --guest-os-features=UEFI_COMPATIBLE,TDX_CAPABLE,VIRTIO_SCSI_MULTIQUEUE

echo ""
echo "==> GCE image ready: $image_name"
echo "    UKI SHA-256: $uki_sha256"
echo "    UKI SHA-384: $uki_sha384 (expected RTMR[1] boot-application event)"
if [ -n "$ephemeral_key" ]; then
    echo "    WARNING: built with --ephemeral-key, the TD gets a new key on every boot"
fi
echo ""
echo "Next: $script_dir/gcp-create-instance.sh --name <instance> --image $image_name"
