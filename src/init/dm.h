// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef DM_H
#define DM_H

#include <inttypes.h>

struct dm_target {
	uint64_t start;
	uint64_t size;
	char *ttype;
	char *params;
};

int create_device(const char *name, const struct dm_target *target);
int get_device_status(const char *name, struct dm_target *out_target);
int suspend_device(const char *name);
int reload_table(const char *name, const struct dm_target *target);
int resume_device(const char *name);
int update_device_nodes(void);

#endif
