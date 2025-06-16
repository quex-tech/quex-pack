# ubuntu:noble-20250415.1
FROM ubuntu@sha256:dc17125eaac86538c57da886e494a34489122fb6a3ebb6411153d742594c2ddc

# Install Ubuntu packages
ARG LD_LINUX_SO_SHA256=6c5e1b4528b704dc7081aa45b5037bda4ea9cad78ca562b4fb6b0dbdbfc7e7e7
ARG LIBC_SO_SHA256=e7a914a33fd4f6d25057b8d48c7c5f3d55ab870ec4ee27693d6c5f3a532e6226
ARG EFI_STUB_SHA256=078e09f18b7754a7a542814c0a30ce059743d6ff334a282a288b7cf23b11662f
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  --mount=type=bind,source=./src/vendor/repro-sources-list/repro-sources-list.sh,target=/usr/local/bin/repro-sources-list.sh \
  <<EOF
#!/bin/bash
set -euo pipefail
repro-sources-list.sh
DEBIAN_FRONTEND=noninteractive \
  apt install -y --no-install-recommends --update \
  autoconf \
  automake \
  bc \
  bison \
  build-essential \
  ca-certificates \
  cpio \
  cryptsetup \
  curl \
  fakeroot \
  flex \
  gcc \
  git \
  go-md2man \
  gzip \
  jq \
  libcap-dev \
  libelf-dev \
  libncurses-dev \
  libprotobuf-c-dev \
  libseccomp-dev \
  libssl-dev \
  libsystemd-dev \
  libtool \
  libyajl-dev \
  make \
  pkgconf \
  python3 \
  rsync \
  skopeo \
  squashfs-tools \
  systemd-boot-efi=255.4-1ubuntu8.6 \
  systemd-ukify \
  umoci \
  xxd
rm -rf /var/log/* /var/cache/ldconfig/aux-cache
cd /usr/lib
sha256sum x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  x86_64-linux-gnu/libc.so.6 \
  systemd/boot/efi/linuxx64.efi.stub
sha256sum -c <<<"$LD_LINUX_SO_SHA256  x86_64-linux-gnu/ld-linux-x86-64.so.2
$LIBC_SO_SHA256  x86_64-linux-gnu/libc.so.6
$EFI_STUB_SHA256  systemd/boot/efi/linuxx64.efi.stub"
EOF

ARG ROOTFS_DIR=/var/rootfs
ARG SOURCE_DATE_EPOCH

#Build Linux
COPY src/linux /tmp/linux-config
ARG LINUX_VERSION=6.12.29
ARG LINUX_TAR_XZ_SHA256=e8b2ec7e2338ccb9c86de7154f6edcaadfce80907493c143e85a82776bb5064d
ADD --checksum=sha256:$LINUX_TAR_XZ_SHA256 https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${LINUX_VERSION}.tar.xz /tmp/linux/linux.tar.xz
ARG LINUX_BZIMAGE_SHA256=5d06292d0844038bb96dfe50d5ed1ec8899fe0cfe6560a81e392cee2e2efbe50

RUN <<EOF
#!/bin/bash
set -euo pipefail
cd /tmp/linux
tar -x -f linux.tar.xz
cd linux-${LINUX_VERSION}
cp /tmp/linux-config/kernel.config .config
export KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_USER=quex
export KBUILD_BUILD_HOST=quex
export KBUILD_BUILD_TIMESTAMP="$(LC_ALL=C TZ=\"UTC\" date -d @$SOURCE_DATE_EPOCH)"
make -j$(nproc)
sha256sum arch/x86/boot/bzImage
sha256sum -c <<<"$LINUX_BZIMAGE_SHA256  arch/x86/boot/bzImage"
mkdir -p /var/linux
cp arch/x86/boot/bzImage /var/linux/
scripts/kconfig/merge_config.sh .config /tmp/linux-config/kernel_debug.config
make -j$(nproc)
cp arch/x86/boot/bzImage /var/linux/debug.bzImage
rm -rf /tmp/linux
EOF

# Build crun
ARG CRUN_VERSION=1.21
ARG CRUN_TAR_GZ_SHA256=4bfb700e764a4804a4de3ecf07753f4c391005356d60356df65d80ae0914c486
ADD --checksum=sha256:$CRUN_TAR_GZ_SHA256 https://github.com/containers/crun/releases/download/${CRUN_VERSION}/crun-${CRUN_VERSION}.tar.gz /tmp/crun/crun.tar.gz
ARG CRUN_BIN_SHA256=5fca2c7b21b4182f10bbaaafb10ac5131d74f66bfba2fad61a4cd9190d0af206
RUN <<EOF
#!/bin/bash
set -euo pipefail
cd /tmp/crun
tar -x -f crun.tar.gz
cd crun-${CRUN_VERSION}
./autogen.sh
mkdir -p ${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu
./configure \
  --prefix ${ROOTFS_DIR}/usr \
  --libdir=${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu \
  --disable-shared \
  --disable-static \
  --disable-libcrun \
  --enable-embedded-yajl \
  --disable-caps \
  --disable-dl \
  --disable-seccomp \
  --disable-systemd \
  --disable-criu
make -j$(nproc)
sha256sum crun
sha256sum -c <<<"$CRUN_BIN_SHA256  crun"
make install
rm -rf /tmp/crun
EOF

# Build init
ARG INIT_BIN_SHA256=14786ab79e56fafa99f78915410dd7a7aeb3090a635634fd4c7154370d70b018
ARG LIBTDX_ATTEST_SO_SHA256=d26f8ac5df799edc6bce92f7b45c46fe03cc3841ef64e542b7c2e7d44d789820
COPY src/init /tmp/init
RUN <<EOF
#!/bin/bash
set -euo pipefail
cd /tmp/init
make clean
make
sha256sum init vendor/build/usr/lib/x86_64-linux-gnu/libtdx_attest.so
sha256sum -c <<<"$INIT_BIN_SHA256  init
$LIBTDX_ATTEST_SO_SHA256  vendor/build/usr/lib/x86_64-linux-gnu/libtdx_attest.so"
mkdir -p ${ROOTFS_DIR}/usr/lib
cp init ${ROOTFS_DIR}/
cp -a vendor/build/usr/lib/x86_64-linux-gnu ${ROOTFS_DIR}/usr/lib/
rm -rf /tmp/init
EOF

# Create directories and copy shared libraries
RUN <<EOF
#!/bin/bash
set -euo pipefail
for dirname in proc sys var/data usr/lib/x86_64-linux-gnu; do
  mkdir -p ${ROOTFS_DIR}/${dirname}
done
cp -a /bin ${ROOTFS_DIR}/
cp -a /lib ${ROOTFS_DIR}/
cp -a /lib64 ${ROOTFS_DIR}/
cp -a /usr/lib64 ${ROOTFS_DIR}/usr/
for libname in ld-linux-x86-64 libc; do
  cp -a /usr/lib/x86_64-linux-gnu/${libname}.so.* ${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu/
done
EOF

# Finalize rootfs and verify its checksum
COPY rootfs ${ROOTFS_DIR}
ARG BASE_ROOTFS_CPIO_GZ_SHA256=0b46cd0ebfc05f8ff5bc6ff7c7df973365f9461c27e21d80ff2f94bd55671cd6
RUN <<EOF
#!/bin/bash
set -euo pipefail
cd ${ROOTFS_DIR}
find . -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
LC_ALL=C find . \
  | LC_ALL=C sort \
  | cpio --reproducible -o -V -H newc \
  | gzip -9 -c -n >/tmp/base-rootfs.cpio.gz
sha256sum /tmp/base-rootfs.cpio.gz
sha256sum -c <<<"$BASE_ROOTFS_CPIO_GZ_SHA256  /tmp/base-rootfs.cpio.gz"
rm /tmp/base-rootfs.cpio.gz
EOF

ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

COPY src/pack/*.sh /usr/local/bin/
ENTRYPOINT ["/bin/bash", "/usr/local/bin/pack-uki.sh"]
