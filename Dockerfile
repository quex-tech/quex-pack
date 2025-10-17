# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies

# ubuntu:noble-20250805
FROM ubuntu@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8 AS builder
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

ARG REPRO_SOURCES_LIST_VERSION=0.1.4
ARG REPRO_SOURCES_LIST_SHA256=c125df9762b0c7233459087bb840c0e5dbfc4d9690ee227f1ed8994f4d51d2e0
ADD --checksum=sha256:$REPRO_SOURCES_LIST_SHA256 --chmod=755 https://raw.githubusercontent.com/reproducible-containers/repro-sources-list.sh/refs/tags/v${REPRO_SOURCES_LIST_VERSION}/repro-sources-list.sh /usr/local/bin/repro-sources-list.sh

# Install Ubuntu packages
ARG LD_LINUX_SO_SHA256=4f961aefd1ecbc91b6de5980623aa389ca56e8bfb5f2a1d2a0b94b54b0fde894
ARG LIBC_SO_SHA256=de259f5276c4a991f78bf87225d6b40e56edbffe0dcbc0ffca36ec7fe30f3f77
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  <<EOF
repro-sources-list.sh
DEBIAN_FRONTEND=noninteractive \
  apt-get install -y --no-install-recommends --update \
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
  git \
  gzip \
  libcap-dev \
  libelf-dev \
  libncurses-dev \
  libprotobuf-c-dev \
  libseccomp-dev \
  libssl-dev \
  libsystemd-dev \
  libtool \
  libyajl-dev \
  pkgconf \
  python3 \
  rsync
rm -rf /var/log/* /var/cache/ldconfig/aux-cache /var/lib/apt/lists/*
cd /usr/lib
sha256sum x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  x86_64-linux-gnu/libc.so.6
sha256sum -c <<<"$LD_LINUX_SO_SHA256  x86_64-linux-gnu/ld-linux-x86-64.so.2
$LIBC_SO_SHA256  x86_64-linux-gnu/libc.so.6"
EOF

ARG ROOTFS_DIR=/var/rootfs
ARG SOURCE_DATE_EPOCH

#Build Linux
COPY src/linux /tmp/linux-config
ARG LINUX_VERSION=6.12.45
ARG LINUX_TAR_XZ_SHA256=8f95a8549cfbdfb89c1181a1f55a971f04dfcd629508a2ed70b777ab92f9db3e
ADD --checksum=sha256:$LINUX_TAR_XZ_SHA256 https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${LINUX_VERSION}.tar.xz /tmp/linux/linux.tar.xz
ARG LINUX_BZIMAGE_SHA256=c82bcd8de6f1589930564127abad8912fe094c069ba821948710ec5c237ff2b4
RUN <<EOF
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
ARG CRUN_BIN_SHA256=7d9ec70dbf2c211958721d26392e20b0a857ce14f5382c0762957402912ac316
RUN <<EOF
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

# Build e2fsprogs
ARG E2FS_VERSION=1.47.1
ARG E2FS_TAR_GZ_SHA256=0d2e0bf80935c3392b73a60dbff82d8a6ef7ea88b806c2eea964b6837d3fd6c2
ARG E2FS_BIN_SHA256=d4fd4a539edf336733c0f7694cabeae4aa22f29e9b632836cbecf960c561129a
ADD --checksum=sha256:$E2FS_TAR_GZ_SHA256 https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v${E2FS_VERSION}/e2fsprogs-${E2FS_VERSION}.tar.gz /tmp/e2fs/e2fs.tar.gz
RUN <<EOF
cd /tmp/e2fs
tar -x -f e2fs.tar.gz
cd e2fsprogs-${E2FS_VERSION}
./configure --prefix ${ROOTFS_DIR}/usr \
		--with-systemd-unit-dir= \
		--with-udev-rules-dir= \
		--with-crond-dir= \
		--disable-testio-debug \
		--enable-libuuid \
		--disable-backtrace \
		--disable-debugfs \
		--disable-imager \
		--disable-resizer \
		--disable-defrag \
		--disable-tls \
		--disable-uuidd \
		--disable-mmp \
		--disable-tdb \
		--disable-bmap-stats \
		--disable-nls \
		--disable-rpath \
		--disable-largefile \
		--disable-fuse2fs \
		--without-pthread \
		--without-libiconv-prefix \
		--without-libintl-prefix \
		--without-libarchive
make libs
make -C ./misc mke2fs.static
sha256sum ./misc/mke2fs.static
sha256sum -c <<<"$E2FS_BIN_SHA256  ./misc/mke2fs.static"
cp ./misc/mke2fs.static ${ROOTFS_DIR}/usr/bin/mke2fs
rm -rf /tmp/e2fs
EOF

# Build init
ARG INIT_CFLAGS=""
ARG INIT_BIN_SHA256=8e3b2fa4a8789009b1891ed7afd6169daf726709fad713d80ad4a02bcbf82321
ARG LIBDEVMAPPER_SO_SHA256=b94e3b648b0aece4ab0abaf6346b0ac5eb418882720d306cdbaf09d6f4788af5
ARG LIBTDX_ATTEST_SO_SHA256=d26f8ac5df799edc6bce92f7b45c46fe03cc3841ef64e542b7c2e7d44d789820
COPY src/init /tmp/init
RUN <<EOF
set -x
cd /tmp/init
make clean
make test CFLAGS="$INIT_CFLAGS"
make CFLAGS="$INIT_CFLAGS"
sha256sum init vendor/build/usr/lib/libdevmapper.so vendor/build/usr/lib/x86_64-linux-gnu/libtdx_attest.so
sha256sum -c <<<"$INIT_BIN_SHA256  init
$LIBDEVMAPPER_SO_SHA256  vendor/build/usr/lib/libdevmapper.so
$LIBTDX_ATTEST_SO_SHA256  vendor/build/usr/lib/x86_64-linux-gnu/libtdx_attest.so"
mkdir -p ${ROOTFS_DIR}/usr/lib ${ROOTFS_DIR}/usr/bin
cp init ${ROOTFS_DIR}/
cp -a vendor/build/usr/lib/libdevmapper.so* ${ROOTFS_DIR}/usr/lib/
cp -a vendor/build/usr/lib/x86_64-linux-gnu ${ROOTFS_DIR}/usr/lib/
rm -rf /tmp/init
EOF

# Create directories and copy shared libraries
RUN <<EOF
for dirname in proc sys mnt/bundle mnt/storage var/data usr/lib/x86_64-linux-gnu; do
  mkdir -p ${ROOTFS_DIR}/${dirname}
done
cp -a /bin ${ROOTFS_DIR}/
cp -a /lib ${ROOTFS_DIR}/
cp -a /lib64 ${ROOTFS_DIR}/
cp -a /usr/lib64 ${ROOTFS_DIR}/usr/
for libname in ld-linux-x86-64 libc libm; do
  cp -a /usr/lib/x86_64-linux-gnu/${libname}.so.* ${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu/
done
EOF

# Finalize rootfs and verify its checksum
COPY rootfs ${ROOTFS_DIR}
ARG ROOTFS_CPIO_GZ_SHA256=c441930a6e126bde4aba7456aca26378129ffacb8171a5d949fda7fc8dd7f21b
RUN <<EOF
cd ${ROOTFS_DIR}
find . -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
LC_ALL=C find . \
  | LC_ALL=C sort \
  | cpio --reproducible -o -V -H newc \
  | gzip -9 -c -n >/var/rootfs.cpio.gz
sha256sum /var/rootfs.cpio.gz
sha256sum -c <<<"$ROOTFS_CPIO_GZ_SHA256  /var/rootfs.cpio.gz"
EOF

# ubuntu:noble-20250805
FROM ubuntu@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

COPY --from=builder /usr/local/bin/repro-sources-list.sh /usr/local/bin/repro-sources-list.sh

# Install Ubuntu packages
ARG EFI_STUB_SHA256=e5c5ec997fa117d6151e80c3bf965d53d4723d0277192f535be70a7023088fc2
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  <<EOF
repro-sources-list.sh
DEBIAN_FRONTEND=noninteractive \
  apt-get install -y --no-install-recommends --update \
  ca-certificates \
  cpio \
  cryptsetup \
  gzip \
  jq \
  skopeo \
  squashfs-tools \
  systemd-boot-efi=255.4-1ubuntu8.10 \
  systemd-ukify \
  umoci
rm -rf /var/log/* /var/cache/ldconfig/aux-cache /var/lib/apt/lists/*
cd /usr/lib
sha256sum systemd/boot/efi/linuxx64.efi.stub
sha256sum -c <<<"$EFI_STUB_SHA256  systemd/boot/efi/linuxx64.efi.stub"
EOF

COPY --from=builder /var/linux /var/linux
COPY --from=builder /var/rootfs /var/rootfs
COPY --from=builder /var/rootfs.cpio.gz /var/rootfs.cpio.gz
COPY src/pack/*.sh /usr/local/bin/

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

ENTRYPOINT ["/bin/bash", "/usr/local/bin/pack.sh"]
