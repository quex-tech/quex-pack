// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef MOUNT_H
#define MOUNT_H

struct mount_spec {
	const char *source;
	const char *target;
	const char *fstype;
	unsigned long flags;
};

int parse_mount_spec(char *input, struct mount_spec *out_spec);

#endif
