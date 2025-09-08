#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <source-image>" >&2
  exit 1
fi

IMAGE_SRC=$1

work=/tmp/work
oci_layout=$work/oci
rootfs=/var/rootfs
bundle=$work/bundle

mkdir -p "$work" "$bundle"
skopeo copy "$IMAGE_SRC" "oci:$oci_layout:latest"
umoci unpack --image "$oci_layout:latest" "$bundle"

jq '
    .process                          = (.process                          // {})
  | .process.env                      = (.process.env                      // [])
  | .mounts                           = (.mounts                           // [])
  | .linux                            = (.linux                            // {})
  | .linux.devices                    = (.linux.devices                    // [])
  | .linux.namespaces                 = (.linux.namespaces                 // [])
  | .linux.resources                  = (.linux.resources                  // {})
  | .linux.resources.devices          = (.linux.resources.devices          // [])
  | .process.terminal = false
  | if (any(.process.env[]?; startswith("TD_SECRET_KEY=")) | not)
      then .process.env += ["TD_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
      else .
    end
  | .mounts |= map(select(.type != "devpts"))
  | .linux.namespaces |= map(select(.type != "network"))
  | if (any(.mounts[]?; .destination == "/sys/kernel/config") | not)
      then .mounts += [{
        "destination": "/sys/kernel/config",
        "type":        "bind",
        "source":      "/sys/kernel/config",
        "options":     ["rbind","rw","nosuid","nodev","noexec"]
      }]
      else .
    end
  | if (any(.mounts[]?; .destination == "/var/data") | not)
        then .mounts += [{
          "destination": "/var/data",
          "type":        "bind",
          "source":      "/var/data",
          "options":     ["rbind","ro","nosuid","nodev","noexec"]
        }]
        else .
      end
  | if (any(.mounts[]?; .destination == "/mnt") | not)
      then .mounts += [{
        "destination": "/mnt",
        "type":        "bind",
        "source":      "/mnt/storage",
        "options":     ["rbind","rw","nosuid","nodev"]
      }]
      else .
    end
  | if (any(.linux.devices[]?; .path == "/dev/tdx_guest") | not)
      then .linux.devices += [{
        "path":      "/dev/tdx_guest",
        "type":      "c",
        "major":     10,
        "minor":     126,
        "fileMode":  438,
        "uid":       0,
        "gid":       0
      }]
      else .
    end
  | if (any(.linux.resources.devices[]?; (.major == 10) and (.minor == 126)) | not)
      then .linux.resources.devices += [{
        "allow":  true,
        "type":   "c",
        "major":  10,
        "minor":  126,
        "access": "rwm"
      }]
      else .
    end
' -c "$bundle/config.json" >"$bundle/config.json.new"
mv "$bundle/config.json.new" "$bundle/config.json"
rm "$bundle/umoci.json" "$bundle/"*.mtree
mkdir -p "$bundle/rootfs/proc" "$bundle/rootfs/dev" "$bundle/rootfs/sys" "$bundle/rootfs/var/data" "$bundle/rootfs/mnt"
find "$bundle" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

workload_dest=${QUEX_WORKLOAD_DESTINATION:-initramfs}
kernel_cmdline="${QUEX_KERNEL_CMDLINE}"
init_args="key_request_mask=$QUEX_KEY_REQUEST_MASK vault_mrenclave=$QUEX_VAULT_MRENCLAVE"

case "$workload_dest" in
disk)
  pack-disk.sh $bundle /mnt/out/disk.img $work/verity.table
  table=$(cat $work/verity.table)
  cp /var/rootfs.cpio.gz /mnt/out/rootfs.cpio.gz
  kernel_cmdline="$kernel_cmdline dm-mod.create=\"workload,,,ro,$table\""
  init_args="$init_args mount=/dev/mapper/workload:/mnt/bundle:squashfs:ro: workload=/mnt/bundle"
  ;;

initramfs | "")
  mkdir -p "$rootfs/opt"
  cp -aT "$bundle" "$rootfs/opt/bundle"
  find "$rootfs" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
  echo "Packing rootfs.cpio.gz"
  (cd "$rootfs" &&
    LC_ALL=C find . |
    LC_ALL=C sort |
      cpio --reproducible -o -H newc) |
    gzip -9 -c -n >"/mnt/out/rootfs.cpio.gz"
  init_args="$init_args workload=/opt/bundle"
  ;;

*)
  echo "Unsupported QUEX_WORKLOAD_DESTINATION='$workload_dest'; expected 'disk' or 'initramfs'." >&2
  exit 1
  ;;
esac

if [ "$QUEX_EXTRA_INIT_ARGS" ]; then
  init_args="$init_args $QUEX_EXTRA_INIT_ARGS"
fi

kernel_cmdline="$kernel_cmdline -- $init_args"

cp $QUEX_KERNEL_PATH /mnt/out/bzImage

ukify build \
  --linux=/mnt/out/bzImage \
  --initrd=/mnt/out/rootfs.cpio.gz \
  --cmdline="$kernel_cmdline" \
  --output=/mnt/out/ukernel.efi

cd /mnt/out
echo "SHA-256"
sha256sum *
echo "SHA-384"
sha384sum *
echo "Kernel command line: '$kernel_cmdline'"
