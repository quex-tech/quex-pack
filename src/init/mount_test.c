// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "mount.h"
#include "test.h"
#include <string.h>
#include <sys/mount.h>

void test_mount(void);

static void test_parse_mount_spec_basic_ok(void) {
	char valid[] = "/dev/vda1:/mnt/data:ext4:ro,noexec,nosuid";
	struct mount_spec spec = {0};

	must(parse_mount_spec(valid, &spec) == 0, "parse_mount_spec must succeed");
	must(strcmp(spec.source, "/dev/vda1") == 0, "source must be /dev/vda1");
	must(strcmp(spec.target, "/mnt/data") == 0, "target must be /mnt/data");
	must(strcmp(spec.fstype, "ext4") == 0, "fstype must be ext4");

	unsigned long expected_flags = MS_RDONLY | MS_NOEXEC | MS_NOSUID;
	must(spec.flags == expected_flags, "flags must be RDONLY | NOEXEC | NOSUID");
}

static void test_parse_mount_spec_rw_and_flags(void) {
	char valid[] = "src:dst:xfs:rw,relatime,nodev";
	struct mount_spec spec = {0};

	must(parse_mount_spec(valid, &spec) == 0, "parse_mount_spec must succeed");
	must(strcmp(spec.fstype, "xfs") == 0, "fstype must be xfs");
	must((spec.flags & MS_RDONLY) == 0, "rw must clear RDONLY");

	unsigned long expected_flags = MS_RELATIME | MS_NODEV;
	must(spec.flags == expected_flags, "flags must be RELATIME | NODEV");
}

static void test_parse_mount_spec_no_options(void) {
	char valid[] = "src:/mnt:ext4";
	struct mount_spec spec = {0};

	must(parse_mount_spec(valid, &spec) == 0, "parse_mount_spec (no options) must succeed");
	must(spec.flags == 0, "flags must be 0 when no options are provided");
}

static void test_parse_mount_spec_unknown_option_ignored(void) {
	char valid[] = "s:t:ext4:florb,ro";
	struct mount_spec spec = {0};

	must(parse_mount_spec(valid, &spec) == 0, "parse_mount_spec must succeed");
	must(spec.flags == MS_RDONLY, "only known option ro must be applied");
}

static void test_parse_mount_spec_invalid(void) {
	struct mount_spec spec = {0};
	char no_fstype[] = "src:dst";
	char no_target[] = "src::ext4";
	char no_source[] = ":dst:ext4";

	must(parse_mount_spec(NULL, &spec) == -1, "NULL input must fail");
	must(parse_mount_spec(no_fstype, &spec) == -1, "missing fstype must fail");
	must(parse_mount_spec(no_target, &spec) == -1, "missing target must fail");
	must(parse_mount_spec(no_source, &spec) == -1, "missing source must fail");

	char valid[] = "src:dst:ext4";
	must(parse_mount_spec(valid, NULL) == -1, "NULL output must fail");
}

void test_mount(void) {
	test_parse_mount_spec_basic_ok();
	test_parse_mount_spec_rw_and_flags();
	test_parse_mount_spec_no_options();
	test_parse_mount_spec_unknown_option_ignored();
	test_parse_mount_spec_invalid();
}
