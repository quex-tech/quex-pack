#!/bin/bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <source-image>" >&2
  exit 1
fi

IMAGE_SRC=$1

work=/tmp/work
oci_layout=$work/oci
rootfs=/var/rootfs
bundle=$rootfs/opt/bundle
SOURCE_DATE_EPOCH=$(cat /tmp/source_date_epoch)

mkdir -p "$work" "$bundle"
skopeo copy "$IMAGE_SRC" "oci:$oci_layout:latest"
umoci unpack --image "$oci_layout:latest" "$bundle"

jq '
    .process                          = (.process                          // {})
  | .mounts                           = (.mounts                           // [])
  | .linux                            = (.linux                            // {})
  | .linux.devices                    = (.linux.devices                    // [])
  | .linux.namespaces                 = (.linux.namespaces                 // [])
  | .linux.resources                  = (.linux.resources                  // {})
  | .linux.resources.devices          = (.linux.resources.devices          // [])
  | .process.terminal = false
  | .mounts |= map(select(.type != "devpts"))
  | .linux.namespaces |= map(select(.type != "network"))
  | .mounts += [{
      "destination": "/sys/kernel/config",
      "type":        "bind",
      "source":      "/sys/kernel/config",
      "options":     ["rbind", "rw", "nosuid", "nodev", "noexec"]
    }]
  | .linux.devices += [{
      "path":      "/dev/tdx_guest",
      "type":      "c",
      "major":     10,
      "minor":     126,
      "fileMode":  438,
      "uid":       0,
      "gid":       0
    }]
  | .linux.resources.devices += [{
      "allow":  true,
      "type":   "c",
      "major":  10,
      "minor":  126,
      "access": "rwm"
    }]
' "$bundle/config.json" >"$bundle/config.json.new"
mv "$bundle/config.json.new" "$bundle/config.json"
rm "$bundle/umoci.json" "$bundle/"*.mtree

find "$rootfs" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

echo "Packing rootfs.cpio.gz"
( cd "$rootfs" && \
  LC_ALL=C find . \
  | LC_ALL=C sort \
  | cpio --reproducible -o -H newc ) \
  | gzip -9 -c -n >"/mnt/out/rootfs.cpio.gz"

ukify build \
  --linux=/var/linux/bzImage \
  --initrd=/mnt/out/rootfs.cpio.gz \
  --cmdline="${QUEX_KERNEL_CMDLINE:-console=ttynull}" \
  --output=/mnt/out/ukernel.efi
