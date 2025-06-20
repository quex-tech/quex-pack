LVM_VERSION := 2_03_32
LVM_URL := https://github.com/lvmteam/lvm2/archive/refs/tags/v$(LVM_VERSION).tar.gz
LVM_TAR_GZ := $(VENDOR_DOWNLOADS_DIR)/v$(LVM_VERSION).tar.gz
LVM_SRC_DIR := $(VENDOR_SRC_DIR)/lvm2-$(LVM_VERSION)
LVM_STAMP := $(VENDOR_DIR)/.lvm-built-stamp

.PHONY: lvm
lvm: $(LVM_STAMP)

$(LVM_STAMP): $(LVM_SRC_DIR)
	@cd $(LVM_SRC_DIR) && ./configure --prefix $(VENDOR_OUT_DIR)/usr \
		--disable-shared \
		--enable-static_link \
		--disable-readline \
		--disable-realtime \
		--disable-use-lvmlockd \
		--disable-use-lvmpolld \
		--disable-systemd-journal \
		--disable-app-machineid \
		--disable-sd-notify \
		--disable-blkid_wiping \
		--disable-nvme-wwid \
		--disable-fsadm \
		--disable-lvmimportvdo \
		--disable-blkdeactivate \
		--disable-selinux \
		--disable-blkzeroout \
		--without-blkid \
		--without-libnvme \
		--without-systemd \
		--without-udev
	@$(MAKE) -C $(LVM_SRC_DIR) device-mapper
	@$(MAKE) -C $(LVM_SRC_DIR) install_device-mapper
	@touch $@

$(LVM_SRC_DIR): $(LVM_TAR_GZ)
	@mkdir -p $(VENDOR_SRC_DIR)
	@tar -xf $< -C $(VENDOR_SRC_DIR)

$(LVM_TAR_GZ):
	@mkdir -p $(VENDOR_DOWNLOADS_DIR)
	@curl -L $(LVM_URL) -o $@
