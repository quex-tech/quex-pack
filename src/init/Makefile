# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
CC ?= gcc
CFLAGS ?=

LOCAL_CFLAGS := -MMD -MP -O2 -Wall -Wextra -Werror -fanalyzer \
  -Wshadow -Wdouble-promotion -Wformat=2 -Wformat-truncation \
  -Wconversion -Wstrict-aliasing=3 -Wnull-dereference \
  -Wuninitialized -Wvla -Walloca

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VENDOR_DIR := $(MAKEFILE_DIR)vendor
VENDOR_DOWNLOADS_DIR := $(VENDOR_DIR)/downloads
VENDOR_SRC_DIR := $(VENDOR_DIR)/src
VENDOR_OUT_DIR := $(VENDOR_DIR)/build

SRCS := init.c key.c report.c quote.c der.c ec.c integrity_crypt.c mount.c mkfs.c dm.c utils.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

OUT := init

INCLUDES := -I$(VENDOR_OUT_DIR)/usr/include -I$(VENDOR_OUT_DIR)/usr/lib/sgx-sdk/include
LIBDIRS := -L$(VENDOR_OUT_DIR)/usr/lib -L$(VENDOR_OUT_DIR)/usr/lib/x86_64-linux-gnu
LIBS := -lmbedx509 -lmbedcrypto -ltdx_attest -ldevmapper -lm -lext2fs -luuid -lcom_err

COMPILE.c = $(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(INCLUDES) -c

.PHONY: all clean distclean

all: $(OUT)

define make-download-rule
$(VENDOR_DOWNLOADS_DIR)/$(notdir $(1)):
	@mkdir -p $(VENDOR_DOWNLOADS_DIR)
	@curl -L "$(1)" -o $(VENDOR_DOWNLOADS_DIR)/$(notdir $(1))
endef

include $(VENDOR_DIR)/mbedtls.mk
include $(VENDOR_DIR)/intel.mk
include $(VENDOR_DIR)/lvm.mk
include $(VENDOR_DIR)/e2fsprogs.mk

$(OUT): $(OBJS)
	@$(CC) $(OBJS) $(LOCAL_CFLAGS) $(CFLAGS) $(INCLUDES) $(LIBDIRS) $(LIBS) -o $@

$(OBJS): mbedtls intel lvm e2fsprogs

%.o: %.c
	@echo "CC $<"
	@$(COMPILE.c) $< -o $@

clean:
	@$(RM) -f $(OUT) $(VENDOR_DIR)/.*-stamp
	@$(RM) -rf $(VENDOR_OUT_DIR) $(VENDOR_SRC_DIR)
	@$(RM) -f $(OBJS) $(DEPS)

distclean: clean
	@$(RM) -rf $(VENDOR_DOWNLOADS_DIR)

-include $(DEPS)
