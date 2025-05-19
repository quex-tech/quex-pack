FROM ubuntu:noble-20240407.1

ARG LINUX_VERSION=6.12.29
ARG CRUN_VERSION=1.21
ARG ROOTFS_DIR=/var/rootfs

ENV DEBIAN_FRONTEND=noninteractive
ENV WRITE_SOURCE_DATE_EPOCH=/tmp/source_date_epoch

# Install Ubuntu packages
RUN \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=bind,source=./src/vendor/repro-sources-list/repro-sources-list.sh,target=/usr/local/bin/repro-sources-list.sh \
    <<EOF
#!/bin/bash
set -euo pipefail
repro-sources-list.sh
apt-get update
apt-get install -y --no-install-recommends \
  autoconf automake bc bison build-essential ca-certificates cpio curl fakeroot flex gcc git go-md2man gzip jq libcap-dev libelf-dev libncurses-dev libprotobuf-c-dev libseccomp-dev libssl-dev libsystemd-dev libtool libyajl-dev make pkgconf python3 skopeo umoci
rm -rf /var/log/* /var/cache/ldconfig/aux-cache
EOF

COPY src/linux /tmp/linux-config

#Build Linux
RUN <<EOF
#!/bin/bash
set -euo pipefail
export SOURCE_DATE_EPOCH=$(cat $WRITE_SOURCE_DATE_EPOCH)
export KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_USER=quex
export KBUILD_BUILD_HOST=quex
export KBUILD_BUILD_TIMESTAMP="$(LC_ALL=C TZ=\"UTC\" date -d @$SOURCE_DATE_EPOCH)"
mkdir -p /tmp/linux /var/linux
curl -L https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${LINUX_VERSION}.tar.xz -o /tmp/linux/linux.tar.xz
cd /tmp/linux
tar -x -f linux.tar.xz
cd linux-${LINUX_VERSION}
cp /tmp/linux-config/kernel.config .config
make -j$(nproc)
cp arch/x86/boot/bzImage /var/linux/
rm -rf /tmp/linux
EOF

# Build crun
RUN <<EOF
#!/bin/bash
set -euo pipefail
export SOURCE_DATE_EPOCH=$(cat $WRITE_SOURCE_DATE_EPOCH)
mkdir -p /tmp/crun ${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu
curl -L https://github.com/containers/crun/releases/download/${CRUN_VERSION}/crun-${CRUN_VERSION}.tar.gz -o /tmp/crun/crun.tar.gz
cd /tmp/crun
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
make install
rm -rf ${ROOTFS_DIR}/usr/share
rm -rf /tmp/crun
EOF

COPY src/init /tmp/init

# Build init
RUN <<EOF
#!/bin/bash
set -euo pipefail
export SOURCE_DATE_EPOCH=$(cat $WRITE_SOURCE_DATE_EPOCH)
cd /tmp/init
make clean
make
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

COPY src/pack/pack-rootfs.sh /usr/local/bin/

ENTRYPOINT ["/bin/bash", "/usr/local/bin/pack-rootfs.sh"]
