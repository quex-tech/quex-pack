// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef ARGS_H
#define ARGS_H

#include "integrity_crypt.h"
#include "mkfs.h"
#include "mount.h"
#include <stddef.h>

#define MAX_DISKS 8

struct init_args {
	const char *key_request_mask;
	const char *vault_mrenclave;
	const char *workload_path;
	struct mount_spec mount_specs[MAX_DISKS];
	ptrdiff_t mount_specs_len;
	struct mkfs_spec mkfs_specs[MAX_DISKS];
	ptrdiff_t mkfs_specs_len;
	struct integrity_spec integrity_specs[MAX_DISKS];
	ptrdiff_t integrity_specs_len;
	struct crypt_spec crypt_specs[MAX_DISKS];
	ptrdiff_t crypt_specs_len;
};

int parse_args(int argc, char *argv[], struct init_args *out_args);

#endif
