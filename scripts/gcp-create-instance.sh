#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# gcp-create-instance.sh: start a GCE Confidential VM (TDX) from an image
# built by gcp-build-image.sh.
set -eu

usage() {
    cat <<USAGE
Usage:
  $0 --name NAME --image IMAGE [OPTIONS]

Options:
  -h, --help            display this help text
  --name NAME           instance name (required)
  --image IMAGE         GCE image built by gcp-build-image.sh (required)
  --project PROJECT     GCP project (default: gcloud config)
  --zone ZONE           GCP zone (default: gcloud config)
  --machine-type TYPE   C3 machine type, TDX needs C3 (default: c3-standard-4)
  --address ADDRESS     reserved static external IP, name or literal (default: ephemeral)
  --disk-size SIZE      boot disk size (default: 10GB)
USAGE
}

name=""
image=""
project=""
zone=""
machine_type="c3-standard-4"
address=""
disk_size="10GB"

while [ $# -gt 0 ]; do
    case $1 in
    -h | --help)
        usage
        exit 0
        ;;
    --name)
        name=$2
        shift 2
        ;;
    --image)
        image=$2
        shift 2
        ;;
    --project)
        project=$2
        shift 2
        ;;
    --zone)
        zone=$2
        shift 2
        ;;
    --machine-type)
        machine_type=$2
        shift 2
        ;;
    --address)
        address=$2
        shift 2
        ;;
    --disk-size)
        disk_size=$2
        shift 2
        ;;
    *)
        echo "Unknown option '$1'" >&2
        usage >&2
        exit 1
        ;;
    esac
done

if [ -z "$name" ] || [ -z "$image" ]; then
    echo "--name and --image are required" >&2
    exit 1
fi
case $machine_type in
c3-*) ;;
*)
    echo "TDX on GCE requires a C3 machine type, got '$machine_type'" >&2
    exit 1
    ;;
esac
if [ -z "$project" ]; then
    project=$(gcloud config get-value project 2>/dev/null || true)
fi
if [ -z "$project" ]; then
    echo "No GCP project: pass --project or run 'gcloud config set project'" >&2
    exit 1
fi

set -- --project="$project" \
    --machine-type="$machine_type" \
    --confidential-compute-type=TDX \
    --maintenance-policy=TERMINATE \
    --boot-disk-type=pd-balanced \
    --boot-disk-size="$disk_size" \
    --image="$image" \
    --image-project="$project"
if [ -n "$zone" ]; then
    set -- "$@" --zone="$zone"
fi
if [ -n "$address" ]; then
    set -- "$@" --address="$address"
fi

echo "==> Creating Confidential VM $name from $image"
gcloud compute instances create "$name" "$@"

echo ""
echo "==> External IP:"
gcloud compute instances describe "$name" --project="$project" ${zone:+--zone="$zone"} \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
echo ""
echo "The TD now waits for its key on port 24516, see docs/gcp.md."
