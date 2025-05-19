CFLAGS ?=
LOCAL_CFLAGS := -O2 -Wall -Wextra -Werror -fanalyzer -Wshadow -Wdouble-promotion -Wformat=2 -Wformat-truncation -Wconversion \
-Wstrict-aliasing=3 -Wnull-dereference -Wuninitialized -Wvla -Walloca
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

MBEDTLS_VERSION := 3.6.3
MBEDTLS_TAR_BZ2 := mbedtls-$(MBEDTLS_VERSION).tar.bz2
MBEDTLS_TAR_BZ2_URL := https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$(MBEDTLS_VERSION)/$(MBEDTLS_TAR_BZ2)
MBEDTLS_DIR := vendor/mbedtls-$(MBEDTLS_VERSION)
MBEDTLS_INC := -I$(MBEDTLS_DIR)/include
MBEDTLS_LIB_DIR := $(MBEDTLS_DIR)/library
MBEDTLS_LIBS := $(MBEDTLS_LIB_DIR)/libmbedx509.a $(MBEDTLS_LIB_DIR)/libmbedcrypto.a
MBEDTLS_CFLAGS := -O2 -I$(MAKEFILE_DIR)/mbedtls_config -DMBEDTLS_CONFIG_FILE='<config.h>'

INTEL_DEB_BASE_URL := https://ppa.launchpadcontent.net/kobuk-team/tdx-attestation-release/ubuntu/pool/main
INTEL_DEB_URLS := \
  $(INTEL_DEB_BASE_URL)/l/linux-sgx/sgx-sdk_2.23.100.2-0ubuntu2.0_amd64.deb \
  $(INTEL_DEB_BASE_URL)/s/sgx-dcap/libtdx-attest-dev_1.21-0ubuntu3.1_amd64.deb \
  $(INTEL_DEB_BASE_URL)/s/sgx-dcap/libtdx-attest1_1.21-0ubuntu3.1_amd64.deb
INTEL_DIR := vendor/intel
INTEL_DEB_FILES := $(notdir $(INTEL_DEB_URLS))
INTEL_DEB_PATHS := $(addprefix $(INTEL_DIR)/,$(INTEL_DEB_FILES))
INTEL_INCLUDE_DIR := $(INTEL_DIR)/usr/include
INTEL_LIB_DIR := $(INTEL_DIR)/usr/lib
INTEL_SGX_SDK_INCLUDE_DIR := $(INTEL_LIB_DIR)/sgx-sdk/include
INTEL_TDX_ATTEST := $(INTEL_LIB_DIR)/x86_64-linux-gnu/libtdx_attest.so

.PHONY: all clean

all: $(MBEDTLS_LIBS) $(INTEL_INCLUDE_DIR) $(INTEL_LIB_DIR) init

vendor/$(MBEDTLS_TAR_BZ2):
	@mkdir -p vendor
	@curl -L $(MBEDTLS_TAR_BZ2_URL) -o $@

$(MBEDTLS_DIR): vendor/$(MBEDTLS_TAR_BZ2)
	@tar -xjf $< -C vendor

$(INTEL_DIR)/%.deb:
	@mkdir -p $(INTEL_DIR)
	@url=$(filter %$*.deb,$(INTEL_DEB_URLS)); \
		curl -L "$$url" -o "$@"

$(INTEL_INCLUDE_DIR) $(INTEL_LIB_DIR): $(INTEL_DEB_PATHS)
	@for deb in $^; do \
		dpkg-deb -x $$deb $(INTEL_DIR); \
	done

init: init.c key.c report.c quote.c der.c ec.c utils.c utils.h types.h $(MBEDTLS_LIBS) $(INTEL_INCLUDE_DIR) $(INTEL_LIB_DIR)
	@$(CC) $(LOCAL_CFLAGS) $(CFLAGS) init.c key.c report.c quote.c der.c ec.c utils.c $(MBEDTLS_LIBS) -o $@ $(MBEDTLS_INC) $(INTEL_TDX_ATTEST) -I$(INTEL_INCLUDE_DIR) -I$(INTEL_SGX_SDK_INCLUDE_DIR)

$(MBEDTLS_LIBS): $(MBEDTLS_DIR) mbedtls_config/config.h
	$(MAKE) -C $(MBEDTLS_DIR) lib CFLAGS="$(MBEDTLS_CFLAGS)"

clean:
	@rm -f init
	@rm -rf $(INTEL_DIR)
	@rm -rf $(MBEDTLS_DIR)
	@rm -f vendor/$(MBEDTLS_TAR_BZ2)
