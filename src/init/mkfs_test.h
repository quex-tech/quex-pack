// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "mkfs.h"
#include "test.h"
#include <string.h>

static void test_parse_mkfs_spec_with_options() {
	char valid[] = "/dev/vdb1:ext4:^64bit,quota";
	struct mkfs_spec spec = {0};

	must(parse_mkfs_spec(valid, &spec) == 0, "parse_mkfs_spec must succeed");
	must(strcmp(spec.dev, "/dev/vdb1") == 0, "dev must be /dev/vdb1");
	must(strcmp(spec.fstype, "ext4") == 0, "fstype must be ext4");
	must(spec.options && strcmp(spec.options, "^64bit,quota") == 0,
	     "options must be ^64bit,quota");
}

static void test_parse_mkfs_spec_without_options() {
	char valid[] = "/dev/vdb2:ext4";
	struct mkfs_spec spec = {0};

	must(parse_mkfs_spec(valid, &spec) == 0, "parse_mkfs_spec (no options) must succeed");
	must(strcmp(spec.dev, "/dev/vdb2") == 0, "dev must be /dev/vdb2");
	must(strcmp(spec.fstype, "ext4") == 0, "fstype must be ext4");
	must(spec.options == NULL, "options must be NULL when absent");
}

static void test_parse_mkfs_spec_invalid() {
	struct mkfs_spec spec = {0};
	char no_fstype[] = "/dev/vdb1";

	must(parse_mkfs_spec(NULL, &spec) == -1, "NULL input must fail");
	must(parse_mkfs_spec(no_fstype, &spec) == -1, "missing fstype must fail");

	char valid[] = "/dev/vdb1:ext4";
	must(parse_mkfs_spec(valid, NULL) == -1, "NULL output must fail");
}

static void test_mkfs() {
	test_parse_mkfs_spec_with_options();
	test_parse_mkfs_spec_without_options();
	test_parse_mkfs_spec_invalid();
}
