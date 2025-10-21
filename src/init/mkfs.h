// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef MKFS_H
#define MKFS_H

struct mkfs_spec {
	const char *dev;
	const char *fstype;
	const char *options;
};

int parse_mkfs_spec(char *input, struct mkfs_spec *out_spec);
int mkfs(const struct mkfs_spec *spec);

#endif
