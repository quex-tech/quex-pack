// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "args.h"
#include "integrity_crypt.h"
#include "mkfs.h"
#include "mount.h"
#include "utils.h"
#include <stddef.h>
#include <string.h>

static int parse_arg(const char *arg, struct init_args *parsed) {
	char *eq = (char *)strchr(arg, '=');
	if (!eq) {
		return 0;
	}

	char *value = eq + 1;

	if (strncmp(arg, "key_request_mask=", strlen("key_request_mask=")) == 0) {
		parsed->key_request_mask = value;
		return 0;
	}

	if (strncmp(arg, "vault_mrenclave=", strlen("vault_mrenclave=")) == 0) {
		parsed->vault_mrenclave = value;
		return 0;
	}

	if (strncmp(arg, "workload=", strlen("workload=")) == 0) {
		if (strlen(value) > 192) {
			trace("Workload path is too long\n");
			return -1;
		}
		parsed->workload_path = value;
		return 0;
	}

	if (strncmp(arg, "integrity=", strlen("integrity=")) == 0) {
		if (parsed->integrity_specs_len >= MAX_DISKS) {
			trace("Too many disks\n");
			return -1;
		}
		int err = parse_integrity_spec(
		    value, &parsed->integrity_specs[parsed->integrity_specs_len++]);
		if (err) {
			trace("parse_integrity_spec failed: %d\n", err);
			return err;
		}
		return 0;
	}

	if (strncmp(arg, "crypt=", strlen("crypt=")) == 0) {
		if (parsed->crypt_specs_len >= MAX_DISKS) {
			trace("Too many disks\n");
			return -1;
		}
		int err = parse_crypt_spec(value, &parsed->crypt_specs[parsed->crypt_specs_len++]);
		if (err) {
			trace("parse_crypt_spec failed: %d\n", err);
			return err;
		}
		return 0;
	}

	if (strncmp(arg, "mkfs=", strlen("mkfs=")) == 0) {
		if (parsed->mkfs_specs_len >= MAX_DISKS) {
			trace("Too many disks\n");
			return -1;
		}
		int err = parse_mkfs_spec(value, &parsed->mkfs_specs[parsed->mkfs_specs_len++]);
		if (err) {
			trace("parse_mkfs_spec failed: %d\n", err);
			return err;
		}
		return 0;
	}

	if (strncmp(arg, "mount=", strlen("mount=")) == 0) {
		if (parsed->mount_specs_len >= MAX_DISKS) {
			trace("Too many disks\n");
			return -1;
		}
		int err = parse_mount_spec(value, &parsed->mount_specs[parsed->mount_specs_len++]);
		if (err) {
			trace("parse_mount_spec failed: %d\n", err);
			return err;
		}
		return 0;
	}

	return 0;
}

int parse_args(int argc, char *argv[], struct init_args *out_args) {
	if (!out_args->key_request_mask) {
		out_args->key_request_mask = "";
	}
	if (!out_args->vault_mrenclave) {
		out_args->vault_mrenclave = "";
	}
	if (!out_args->workload_path) {
		out_args->workload_path = "/opt/bundle";
	}

	for (int i = 1; i < argc; i++) {
		trace("argv[%d] = %s\n", i, argv[i]);
		int err = parse_arg(argv[i], out_args);
		if (err) {
			return err;
		}
	}
	return 0;
}
