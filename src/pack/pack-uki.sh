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
' "$bundle/config.json" >"$bundle/config.json.new"
mv "$bundle/config.json.new" "$bundle/config.json"
rm "$bundle/umoci.json" "$bundle/"*.mtree

if [[ $QUEX_KEY_REQUEST_MASK ]]; then
  echo $QUEX_KEY_REQUEST_MASK | xxd -r -p >"$rootfs/etc/key_request_mask.bin"
fi

if [[ $QUEX_VAULT_MRENCLAVE ]]; then
  echo $QUEX_VAULT_MRENCLAVE | xxd -r -p >"$rootfs/etc/vault_mrenclave.bin"
fi

find "$rootfs" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

echo "Packing rootfs.cpio.gz"
(cd "$rootfs" &&
  LC_ALL=C find . |
  LC_ALL=C sort |
    cpio --reproducible -o -H newc) |
  gzip -9 -c -n >"/mnt/out/rootfs.cpio.gz"

cp /var/linux/bzImage /mnt/out/bzImage

kernel_cmdline="${QUEX_KERNEL_CMDLINE:-console=ttynull}"

ukify build \
  --linux=/mnt/out/bzImage \
  --initrd=/mnt/out/rootfs.cpio.gz \
  --cmdline="${QUEX_KERNEL_CMDLINE:-console=ttynull}" \
  --output=/mnt/out/ukernel.efi

cd /mnt/out
sha384sum *
echo "Kernel command line: '$kernel_cmdline'"
