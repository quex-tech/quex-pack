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

LOCAL_CFLAGS := -O2 -std=c17 -Wall -Wextra -Werror \
  -Wshadow -Wdouble-promotion -Wformat=2 -Wformat-truncation -Wformat-overflow \
  -Wconversion  -Wnull-dereference \
  -Wuninitialized -Wvla -Walloca -Wno-unused-parameter \
  -Wwrite-strings -Wstrict-prototypes -Wold-style-definition \
  -Wredundant-decls -Wnested-externs -Wmissing-include-dirs \
  -fno-common -fstrict-overflow -fstack-protector-strong -Wcast-qual \
  -Wbad-function-cast -Wmissing-prototypes -Wc++-compat

ifeq ($(COMPILER),gcc)
	LOCAL_CFLAGS += -fanalyzer -Wstrict-aliasing=3 -Wlogical-op \
  -Wduplicated-cond -Wduplicated-branches -Wrestrict -Wjump-misses-init
endif

ifeq ($(COMPILER),clang)
	LOCAL_CFLAGS += -Weverything -Wno-padded -Wno-reserved-identifier \
  -Wno-declaration-after-statement -Wno-unsafe-buffer-usage \
  -Wno-documentation-deprecated-sync -Wno-switch-enum -Wno-documentation-pedantic \
  -Wno-disabled-macro-expansion
endif

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VENDOR_DIR := $(MAKEFILE_DIR)vendor
VENDOR_DOWNLOADS_DIR := $(VENDOR_DIR)/downloads
VENDOR_SRC_DIR := $(VENDOR_DIR)/src
VENDOR_OUT_DIR := $(VENDOR_DIR)/build

MODULE_SRCS := key.c report.c quote.c der.c ec.c args.c integrity_crypt.c mount.c mkfs.c dm.c utils.c
MODULE_OBJS := $(MODULE_SRCS:.c=.o)
MODULE_DEPS := $(MODULE_SRCS:.c=.d)

SRCS := init.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)
OUT := init

TEST_SRCS := test.c der_test.c ec_test.c integrity_crypt_test.c key_test.c mkfs_test.c mount_test.c quote_test.c report_test.c utils_test.c mock_tdx.c mock_network.c test_utils.c
TEST_OBJS := $(TEST_SRCS:.c=.o)
TEST_DEPS := $(TEST_SRCS:.c=.d)
TEST_OUT := test.bin
MOCK_NETWORK := -Wl,--wrap=socket -Wl,--wrap=setsockopt -Wl,--wrap=bind -Wl,--wrap=listen -Wl,--wrap=accept -Wl,--wrap=send -Wl,--wrap=recv -Wl,--wrap=__recv_chk -Wl,--wrap=close
MOCK_TDX := -Wl,--wrap=tdx_att_get_quote -Wl,--wrap=tdx_att_free_quote -Wl,--wrap=tdx_att_get_report

FUZZ_CC := clang
FUZZ_CFLAGS := -O1 -g -fsanitize=address,undefined,fuzzer -fprofile-instr-generate -fcoverage-mapping
FUZZ_ARGS ?=

INCLUDES := -I$(VENDOR_OUT_DIR)/usr/include -I$(VENDOR_OUT_DIR)/usr/lib/sgx-sdk/include
CPPFLAGS := -MMD -MP -D_POSIX_C_SOURCE=200809L $(INCLUDES)

LDFLAGS := -L$(VENDOR_OUT_DIR)/usr/lib -L$(VENDOR_OUT_DIR)/usr/lib/x86_64-linux-gnu
LDLIBS := -lmbedx509 -lmbedcrypto -ltdx_attest -ldevmapper -lm
LIBPATHS := $(VENDOR_OUT_DIR)/usr/lib:$(VENDOR_OUT_DIR)/usr/lib/x86_64-linux-gnu

.PHONY: all clean distclean test fuzz_args fuzz_quote lint format

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
	@echo "LD $<"
	@$(CC) $(OBJS) $(MODULE_OBJS) $(LDFLAGS) $(LDLIBS) -o $@

$(TEST_OUT): $(TEST_OBJS)
	@echo "LD $<"
	@$(CC) $(TEST_OBJS) $(MODULE_OBJS) $(LDFLAGS) $(LDLIBS) $(MOCK_NETWORK) $(MOCK_TDX) -o $@

$(OBJS): $(MODULE_OBJS)
$(TEST_OBJS): $(MODULE_OBJS)
$(MODULE_OBJS): mbedtls intel lvm

test: $(TEST_OUT)
	@LD_LIBRARY_PATH=$(LIBPATHS) ./$(TEST_OUT)

ARGS_FUZZ_SRCS := args_fuzz.c
ARGS_FUZZ_OUT := fuzz_args.bin

$(ARGS_FUZZ_OUT): $(ARGS_FUZZ_SRCS) $(MODULE_SRCS)
	@$(FUZZ_CC) $(FUZZ_CFLAGS) $(CPPFLAGS) $(ARGS_FUZZ_SRCS) $(MODULE_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

fuzz_args: $(ARGS_FUZZ_OUT)
	@LD_LIBRARY_PATH=$(LIBPATHS) ./$(ARGS_FUZZ_OUT) -max_len=6000 -dict=./args_fuzz.dict $(FUZZ_ARGS) ./args_fuzz_seeds/

QUOTE_FUZZ_SRCS := quote_fuzz.c
QUOTE_FUZZ_OUT := fuzz_quote.bin

$(QUOTE_FUZZ_OUT): $(QUOTE_FUZZ_SRCS) $(MODULE_SRCS) mbedtls intel lvm
	@$(FUZZ_CC) $(FUZZ_CFLAGS) $(CPPFLAGS) $(QUOTE_FUZZ_SRCS) $(MODULE_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

fuzz_quote: $(QUOTE_FUZZ_OUT)
	@LD_LIBRARY_PATH=$(LIBPATHS) ./$(QUOTE_FUZZ_OUT) -max_len=6000 $(FUZZ_ARGS) ./quote_fuzz_seeds/

lint:
	@clang-format --dry-run -Werror *.c *.h
	@$(foreach s,$(SRCS) $(TEST_SRCS) $(ARGS_FUZZ_SRCS) $(QUOTE_FUZZ_SRCS) $(MODULE_SRCS),include-what-you-use -Xiwyu --error=2 -Xiwyu --mapping_file=iwyu.imp $(CPPFLAGS) $(s) &&) true
	@clang-tidy $(foreach inc,$(INCLUDES),--extra-arg=$(inc)) --warnings-as-errors=* *.c *.h
	@cppcheck --enable=all --library=posix --inconclusive --suppress=missingIncludeSystem -q --inline-suppr --error-exitcode=2 $(SRCS) $(TEST_SRCS) $(MODULE_SRCS)

format:
	@clang-format -i *.c *.h

%.o: %.c
	@echo "CC $<"
	@$(CC) $(CPPFLAGS) $(LOCAL_CFLAGS) $(CFLAGS) -c $< -o $@

clean:
	@$(RM) -f $(OUT) $(TEST_OUT) $(QUOTE_FUZZ_OUT) $(ARGS_FUZZ_OUT) *.o *.d $(VENDOR_DIR)/.*-stamp
	@$(RM) -rf $(VENDOR_OUT_DIR) $(VENDOR_SRC_DIR)

distclean: clean
	@$(RM) -rf $(VENDOR_DOWNLOADS_DIR)

-include $(DEPS)
-include $(TEST_DEPS)
-include $(MODULE_DEPS)