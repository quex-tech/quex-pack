// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "dm.h"
#include "utils.h"
#include <libdevmapper.h>

static int run_simple_task(const char *name, int type) {
	int err = 0;

	struct dm_task *dmt = dm_task_create(type);
	if (!dmt) {
		trace("dm_task_create failed\n");
		err = -1;
		goto cleanup;
	}

	int ok = dm_task_set_name(dmt, name);
	if (!ok) {
		trace("dm_task_set_name failed\n");
		err = -1;
		goto cleanup;
	}

	ok = dm_task_run(dmt);
	if (!ok) {
		trace("dm_task_run failed\n");
		err = -1;
		goto cleanup;
	}

cleanup:
	if (dmt) {
		dm_task_destroy(dmt);
	}
	return err;
}

int create_device(const char *name, const struct dm_target *target) {
	int err = 0;

	struct dm_task *dmt = dm_task_create(DM_DEVICE_CREATE);
	if (!dmt) {
		trace("dm_task_create failed\n");
		err = -1;
		goto cleanup;
	}

	int ok = dm_task_set_name(dmt, name);
	if (!ok) {
		trace("dm_task_set_name failed\n");
		err = -1;
		goto cleanup;
	}

	ok = dm_task_set_add_node(dmt, DM_ADD_NODE_ON_CREATE);
	if (!ok) {
		trace("dm_task_set_add_node failed\n");
		err = -1;
		goto cleanup;
	}

	ok = dm_task_add_target(dmt, target->start, target->size, target->ttype, target->params);
	if (!ok) {
		trace("dm_task_add_target failed\n");
		err = -1;
		goto cleanup;
	}

	ok = dm_task_run(dmt);
	if (!ok) {
		trace("dm_task_run failed\n");
		err = -1;
		goto cleanup;
	}

cleanup:
	if (dmt) {
		dm_task_destroy(dmt);
	}
	return err;
}

int get_device_status(const char *name, struct dm_target *out_target) {
	int err = 0;

	struct dm_task *dmt = dm_task_create(DM_DEVICE_STATUS);
	if (!dmt) {
		trace("dm_task_create failed\n");
		err = -1;
		goto cleanup;
	}

	int ok = dm_task_set_name(dmt, name);
	if (!ok) {
		trace("dm_task_set_name failed\n");
		err = -1;
		goto cleanup;
	}

	ok = dm_task_run(dmt);
	if (!ok) {
		trace("dm_task_run failed\n");
		err = -1;
		goto cleanup;
	}

	char *ttype = NULL;
	char *params = NULL;
	dm_get_next_target(dmt, NULL, &out_target->start, &out_target->size, &ttype, &params);
	out_target->ttype = ttype ? strdup(ttype) : NULL;
	out_target->params = params ? strdup(params) : NULL;
cleanup:
	if (dmt) {
		dm_task_destroy(dmt);
	}
	return err;
}

int suspend_device(const char *name) { return run_simple_task(name, DM_DEVICE_SUSPEND); }

int reload_table(const char *name, const struct dm_target *target) {
	int err = 0;

	struct dm_task *dmt = dm_task_create(DM_DEVICE_RELOAD);
	if (!dmt) {
		err = -1;
		goto cleanup;
	}

	int ok = dm_task_set_name(dmt, name);
	if (!ok) {
		trace("dm_task_set_name failed\n");
		err = -1;
		goto cleanup;
	}

	ok = dm_task_add_target(dmt, target->start, target->size, target->ttype, target->params);
	if (!ok) {
		trace("dm_task_add_target failed\n");
		err = -1;
		goto cleanup;
	}

	ok = dm_task_run(dmt);
	if (!ok) {
		trace("dm_task_run failed\n");
		err = -1;
		goto cleanup;
	}

cleanup:
	if (dmt) {
		dm_task_destroy(dmt);
	}
	return err;
}

int resume_device(const char *name) { return run_simple_task(name, DM_DEVICE_RESUME); }

int update_device_nodes(void) {
	if (!dm_mknodes(NULL)) {
		trace("dm_mknodes failed\n");
		return -1;
	}

	dm_task_update_nodes();

	return 0;
}
