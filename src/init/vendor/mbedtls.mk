MBEDTLS_VERSION := 3.6.3
MBEDTLS_TAR_BZ2 := $(VENDOR_DOWNLOADS_DIR)/mbedtls.tar.bz2
MBEDTLS_TAR_BZ2_URL := https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$(MBEDTLS_VERSION)/mbedtls-$(MBEDTLS_VERSION).tar.bz2
MBEDTLS_CFLAGS := -O2 -I$(MAKEFILE_DIR)/vendor/mbedtls_config -DMBEDTLS_CONFIG_FILE='<config.h>'
MBEDTLS_STAMP := $(VENDOR_DIR)/.mbedtls-built-stamp
MBEDTLS_SRC_DIR := $(VENDOR_SRC_DIR)/mbedtls-$(MBEDTLS_VERSION)

.PHONY: mbedtls
mbedtls: $(MBEDTLS_STAMP)

$(MBEDTLS_STAMP): $(MBEDTLS_SRC_DIR)
	$(MAKE) -C $(MBEDTLS_SRC_DIR) lib CFLAGS="$(MBEDTLS_CFLAGS)"
	@mkdir -p $(VENDOR_OUT_DIR)/usr
	@rsync -av --include='*/' --include='*.h' --exclude='*' $(MBEDTLS_SRC_DIR)/include/ $(VENDOR_OUT_DIR)/usr/include/
	@rsync -av --include='*/' --include='*.a' --exclude='*' $(MBEDTLS_SRC_DIR)/library/ $(VENDOR_OUT_DIR)/usr/lib/
	@touch $@

$(MBEDTLS_SRC_DIR): $(MBEDTLS_TAR_BZ2)
	@mkdir -p $(VENDOR_SRC_DIR)
	@tar -xjf $< -C $(VENDOR_SRC_DIR)

$(MBEDTLS_TAR_BZ2):
	@mkdir -p $(VENDOR_DOWNLOADS_DIR)
	@curl -L $(MBEDTLS_TAR_BZ2_URL) -o $@
