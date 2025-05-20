# ubuntu:noble-20250415.1
FROM ubuntu@sha256:dc17125eaac86538c57da886e494a34489122fb6a3ebb6411153d742594c2ddc

ARG ROOTFS_DIR=/var/rootfs

ENV DEBIAN_FRONTEND=noninteractive

# Install Ubuntu packages
RUN \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=bind,source=./src/vendor/repro-sources-list/repro-sources-list.sh,target=/usr/local/bin/repro-sources-list.sh \
    <<EOF
#!/bin/bash
set -euo pipefail
repro-sources-list.sh
apt install -y --no-install-recommends --update \
  autoconf \
  automake \
  bc \
  bison \
  build-essential \
  ca-certificates \
  cpio \
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
  skopeo \
  systemd-boot-efi=255.4-1ubuntu8.6 \
  systemd-ukify \
  umoci \
  xxd
rm -rf /var/log/* /var/cache/ldconfig/aux-cache
cd /usr/lib
sha256sum x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  x86_64-linux-gnu/libc.so.6 \
  systemd/boot/efi/linuxx64.efi.stub
sha256sum -c <<<"6c5e1b4528b704dc7081aa45b5037bda4ea9cad78ca562b4fb6b0dbdbfc7e7e7  x86_64-linux-gnu/ld-linux-x86-64.so.2
e7a914a33fd4f6d25057b8d48c7c5f3d55ab870ec4ee27693d6c5f3a532e6226  x86_64-linux-gnu/libc.so.6
078e09f18b7754a7a542814c0a30ce059743d6ff334a282a288b7cf23b11662f  systemd/boot/efi/linuxx64.efi.stub"
EOF

ENV SOURCE_DATE_EPOCH=1747699200

COPY src/linux /tmp/linux-config

ARG LINUX_VERSION=6.12.29
ARG LINUX_TAR_XZ_SHA256=e8b2ec7e2338ccb9c86de7154f6edcaadfce80907493c143e85a82776bb5064d
ARG LINUX_BZIMAGE_SHA256=5d06292d0844038bb96dfe50d5ed1ec8899fe0cfe6560a81e392cee2e2efbe50

#Build Linux
RUN <<EOF
#!/bin/bash
set -euo pipefail
export KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_USER=quex
export KBUILD_BUILD_HOST=quex
export KBUILD_BUILD_TIMESTAMP="$(LC_ALL=C TZ=\"UTC\" date -d @$SOURCE_DATE_EPOCH)"
mkdir -p /tmp/linux /var/linux
curl -L https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${LINUX_VERSION}.tar.xz -o /tmp/linux/linux.tar.xz
cd /tmp/linux
sha256sum linux.tar.xz
sha256sum -c <<<"$LINUX_TAR_XZ_SHA256  linux.tar.xz"
tar -x -f linux.tar.xz
cd linux-${LINUX_VERSION}
cp /tmp/linux-config/kernel.config .config
make -j$(nproc)
sha256sum arch/x86/boot/bzImage
sha256sum -c <<<"$LINUX_BZIMAGE_SHA256  arch/x86/boot/bzImage"
cp arch/x86/boot/bzImage /var/linux/
rm -rf /tmp/linux
EOF

ARG CRUN_VERSION=1.21
ARG CRUN_TAR_GZ_SHA256=4bfb700e764a4804a4de3ecf07753f4c391005356d60356df65d80ae0914c486
ARG CRUN_BIN_SHA256=5fca2c7b21b4182f10bbaaafb10ac5131d74f66bfba2fad61a4cd9190d0af206

# Build crun
RUN <<EOF
#!/bin/bash
set -euo pipefail
mkdir -p /tmp/crun ${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu
curl -L https://github.com/containers/crun/releases/download/${CRUN_VERSION}/crun-${CRUN_VERSION}.tar.gz -o /tmp/crun/crun.tar.gz
cd /tmp/crun
sha256sum crun.tar.gz
sha256sum -c <<<"$CRUN_TAR_GZ_SHA256  crun.tar.gz"
tar -x -f crun.tar.gz
cd crun-${CRUN_VERSION}
./autogen.sh
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

ARG INIT_BIN_SHA256=30cd24ca690bed97afb6405ad7c27a3a09fab0ed22e53f1ba5c941c5f2bdec72
ARG LIBTDX_ATTEST_SO_SHA256=d26f8ac5df799edc6bce92f7b45c46fe03cc3841ef64e542b7c2e7d44d789820

COPY src/init /tmp/init

# Build init
RUN <<EOF
#!/bin/bash
set -euo pipefail
cd /tmp/init
make clean
make
sha256sum init vendor/intel/usr/lib/x86_64-linux-gnu/libtdx_attest.so
sha256sum -c <<<"$INIT_BIN_SHA256  init
$LIBTDX_ATTEST_SO_SHA256  vendor/intel/usr/lib/x86_64-linux-gnu/libtdx_attest.so"
mkdir -p ${ROOTFS_DIR}/usr/lib
cp init ${ROOTFS_DIR}/
cp -a vendor/intel/usr/lib/x86_64-linux-gnu ${ROOTFS_DIR}/usr/lib/
rm -rf /tmp/init
EOF

# Create directories and copy shared libraries
RUN <<EOF
#!/bin/bash
set -euo pipefail
for dirname in proc sys usr/lib/x86_64-linux-gnu; do
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

COPY rootfs ${ROOTFS_DIR}

ARG BASE_ROOTFS_CPIO_GZ_SHA256=54777a232bb64c9e3c833b56407bcfe98f6ae4f0a136a7b95852867f0eee34d4

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
EOF

COPY src/pack/pack-uki.sh /usr/local/bin/

ENTRYPOINT ["/bin/bash", "/usr/local/bin/pack-uki.sh"]
