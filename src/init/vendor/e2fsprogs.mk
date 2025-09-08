# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
E2FS_VERSION := 1.47.1
E2FS_URL := https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$(E2FS_VERSION)/e2fsprogs-$(E2FS_VERSION).tar.gz
E2FS_TAR_GZ := $(VENDOR_DOWNLOADS_DIR)/e2fsprogs-$(E2FS_VERSION).tar.gz
E2FS_SRC_DIR := $(VENDOR_SRC_DIR)/e2fsprogs-$(E2FS_VERSION)
E2FS_STAMP := $(VENDOR_DIR)/.e2fsprogs-built-stamp

.PHONY: e2fsprogs
e2fsprogs: $(E2FS_STAMP)

$(E2FS_STAMP): $(E2FS_SRC_DIR)
	@mkdir -p $(VENDOR_OUT_DIR)/usr/bin
	@cd $(E2FS_SRC_DIR) && ./configure --prefix $(VENDOR_OUT_DIR)/usr \
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
	@$(MAKE) -C $(E2FS_SRC_DIR) libs
	@$(MAKE) -C $(E2FS_SRC_DIR)/misc mke2fs.static
	@$(MAKE) -C $(E2FS_SRC_DIR) install-libs
	@cp $(E2FS_SRC_DIR)/misc/mke2fs.static $(VENDOR_OUT_DIR)/usr/bin/mke2fs
	@touch $@

$(E2FS_SRC_DIR): $(E2FS_TAR_GZ)
	@mkdir -p $(VENDOR_SRC_DIR)
	@tar -xf $< -C $(VENDOR_SRC_DIR)

$(E2FS_TAR_GZ):
	@mkdir -p $(VENDOR_DOWNLOADS_DIR)
	@curl -L $(E2FS_URL) -o $@
