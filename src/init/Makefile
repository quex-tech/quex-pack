CC ?= gcc
CFLAGS ?=

LOCAL_CFLAGS := -MMD -MP -O2 -Wall -Wextra -Werror -fanalyzer \
  -Wshadow -Wdouble-promotion -Wformat=2 -Wformat-truncation \
  -Wconversion -Wstrict-aliasing=3 -Wnull-dereference \
  -Wuninitialized -Wvla -Walloca

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VENDOR_DIR := vendor
VENDOR_DOWNLOADS_DIR := $(VENDOR_DIR)/downloads
VENDOR_SRC_DIR := $(VENDOR_DIR)/src
VENDOR_OUT_DIR := $(VENDOR_DIR)/build

SRCS := init.c key.c report.c quote.c der.c ec.c utils.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

OUT := init

INCLUDES := -I$(VENDOR_OUT_DIR)/include -I$(VENDOR_OUT_DIR)/usr/lib/sgx-sdk/include
LIBDIRS := -L$(VENDOR_OUT_DIR)/lib -L$(VENDOR_OUT_DIR)/usr/lib -L$(VENDOR_OUT_DIR)/usr/lib/x86_64-linux-gnu
LIBS := -lmbedx509 -lmbedcrypto -ltdx_attest

COMPILE.c = $(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(INCLUDES) -c

.PHONY: all clean

all: $(OUT)

define make-download-rule
$(VENDOR_DOWNLOADS_DIR)/$(notdir $(1)):
	@mkdir -p $(VENDOR_DOWNLOADS_DIR)
	@curl -L "$(1)" -o $(VENDOR_DOWNLOADS_DIR)/$(notdir $(1))
endef

include $(VENDOR_DIR)/mbedtls.mk
include $(VENDOR_DIR)/intel.mk

$(OUT): $(OBJS)
	@$(CC) $(OBJS) $(LOCAL_CFLAGS) $(CFLAGS) $(INCLUDES) $(LIBDIRS) $(LIBS) -o $@

$(OBJS): mbedtls intel

%.o: %.c
	@$(COMPILE.c) $< -o $@

clean:
	@$(RM) -f $(OUT) $(VENDOR_DIR)/.*-stamp
	@$(RM) -rf $(VENDOR_OUT_DIR) $(VENDOR_SRC_DIR) $(VENDOR_DOWNLOADS_DIR)
	@$(RM) -f $(OBJS) $(DEPS)

-include $(DEPS)
