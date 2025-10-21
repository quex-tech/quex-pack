# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
CC ?= gcc

COMPILER_DEFS := $(shell echo "" | $(CC) -dM -E - 2>/dev/null)
ifeq (,$(findstring __clang__,$(COMPILER_DEFS)))
    ifneq (,$(findstring __GNUC__,$(COMPILER_DEFS)))
        COMPILER := gcc
    else
        COMPILER := $(CC)
    endif
else
    COMPILER := clang
endif

LOCAL_CFLAGS := -MMD -MP -O2 -std=c17 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  -Wshadow -Wdouble-promotion -Wformat=2 -Wformat-truncation -Wformat-overflow \
  -Wconversion  -Wnull-dereference \
  -Wuninitialized -Wvla -Walloca -Wno-unused-parameter \
  -Wwrite-strings -Wstrict-prototypes -Wold-style-definition \
  -Wredundant-decls -Wnested-externs -Wmissing-include-dirs \
  -fno-common -fstrict-overflow -fstack-protector-strong -Wcast-qual \
  -Wbad-function-cast -Wmissing-prototypes

ifeq ($(COMPILER),gcc)
	LOCAL_CFLAGS += -fanalyzer -Wstrict-aliasing=3 -Wlogical-op -Wduplicated-cond -Wduplicated-branches -Wrestrict
endif

ifeq ($(COMPILER),clang)
	LOCAL_CFLAGS += -Wstrict-aliasing=2 -Wnewline-eof
endif

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VENDOR_DIR := $(MAKEFILE_DIR)vendor
VENDOR_DOWNLOADS_DIR := $(VENDOR_DIR)/downloads
VENDOR_SRC_DIR := $(VENDOR_DIR)/src
VENDOR_OUT_DIR := $(VENDOR_DIR)/build

MODULE_SRCS := key.c report.c quote.c der.c ec.c integrity_crypt.c mount.c mkfs.c dm.c utils.c
MODULE_OBJS := $(MODULE_SRCS:.c=.o)
MODULE_DEPS := $(MODULE_SRCS:.c=.d)

SRCS := init.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)
OUT := init

TEST_SRCS := test.c
TEST_OBJS := $(TEST_SRCS:.c=.o)
TEST_DEPS := $(TEST_SRCS:.c=.d)
TEST_OUT := test.bin
MOCK_NETWORK := -Wl,--wrap=socket -Wl,--wrap=setsockopt -Wl,--wrap=bind -Wl,--wrap=listen -Wl,--wrap=accept -Wl,--wrap=send -Wl,--wrap=recv -Wl,--wrap=__recv_chk -Wl,--wrap=close
MOCK_TDX := -Wl,--wrap=tdx_att_get_quote -Wl,--wrap=tdx_att_free_quote -Wl,--wrap=tdx_att_get_report

QUOTE_FUZZ_SRCS := quote_fuzz.c
QUOTE_FUZZ_OUT := quote_fuzz.bin

FUZZ_CC := clang
FUZZ_CFLAGS := -O1 -g -fsanitize=address,undefined,fuzzer

INCLUDES := -I$(VENDOR_OUT_DIR)/usr/include -I$(VENDOR_OUT_DIR)/usr/lib/sgx-sdk/include
LIBDIRS := -L$(VENDOR_OUT_DIR)/usr/lib -L$(VENDOR_OUT_DIR)/usr/lib/x86_64-linux-gnu
LIBS := -lmbedx509 -lmbedcrypto -ltdx_attest -ldevmapper -lm
LIBPATHS := $(VENDOR_OUT_DIR)/usr/lib:$(VENDOR_OUT_DIR)/usr/lib/x86_64-linux-gnu

COMPILE.c = $(CC) $(LOCAL_CFLAGS) $(CFLAGS) $(INCLUDES) -c

.PHONY: all clean distclean test fuzz lint format

all: $(OUT)

define make-download-rule
$(VENDOR_DOWNLOADS_DIR)/$(notdir $(1)):
	@mkdir -p $(VENDOR_DOWNLOADS_DIR)
	@curl -L "$(1)" -o $(VENDOR_DOWNLOADS_DIR)/$(notdir $(1))
endef

include $(VENDOR_DIR)/mbedtls.mk
include $(VENDOR_DIR)/intel.mk
include $(VENDOR_DIR)/lvm.mk

$(OUT): $(OBJS)
	@$(CC) $(OBJS) $(MODULE_OBJS) $(LOCAL_CFLAGS) $(CFLAGS) $(INCLUDES) $(LIBDIRS) $(LIBS) -o $@

$(TEST_OUT): $(TEST_OBJS)
	@$(CC) $(TEST_OBJS) $(MODULE_OBJS) $(LOCAL_CFLAGS) $(CFLAGS) $(INCLUDES) $(LIBDIRS) $(LIBS) $(MOCK_NETWORK) $(MOCK_TDX) -o $@

$(QUOTE_FUZZ_OUT): $(QUOTE_FUZZ_SRCS) $(MODULE_OBJS)
	@$(FUZZ_CC) $(QUOTE_FUZZ_SRCS) $(MODULE_OBJS) -O1 -g -fsanitize=address,undefined,fuzzer $(INCLUDES) $(LIBDIRS) $(LIBS) -o $@

$(OBJS): $(MODULE_OBJS)
$(TEST_OBJS): $(MODULE_OBJS)
$(MODULE_OBJS): mbedtls intel lvm

test: $(TEST_OUT)
	@LD_LIBRARY_PATH=$(LIBPATHS) ./$(TEST_OUT)

quote_fuzz: $(QUOTE_FUZZ_OUT)
	@LD_LIBRARY_PATH=$(LIBPATHS) ./$(QUOTE_FUZZ_OUT) -max_len=6000 ./quote_fuzz_seeds/

lint:
	@clang-format --dry-run -Werror *.c *.h
	@clang-tidy $(foreach inc,$(INCLUDES),--extra-arg=$(inc)) --warnings-as-errors=* *.c *.h
	@cppcheck --enable=all --library=posix --inconclusive --suppress=missingIncludeSystem -q --inline-suppr --error-exitcode=2 *.c *.h

format:
	@clang-format -i *.c *.h

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
-include $(TEST_DEPS)
-include $(MODULE_DEPS)