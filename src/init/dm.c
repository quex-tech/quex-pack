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

	dm_task_set_name(dmt, name);
	int ok = dm_task_run(dmt);
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

	dm_task_set_name(dmt, name);
	dm_task_set_add_node(dmt, DM_ADD_NODE_ON_CREATE);

	int ok =
	    dm_task_add_target(dmt, target->start, target->size, target->ttype, target->params);
	if (!ok) {
		trace("dm_task_add_target failed\n");
		return -1;
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

int get_device_status(const char *name, struct dm_target *target) {
	int err = 0;

	struct dm_task *dmt = dm_task_create(DM_DEVICE_STATUS);
	if (!dmt) {
		trace("dm_task_create failed\n");
		err = -1;
		goto cleanup;
	}

	dm_task_set_name(dmt, name);
	int ok = dm_task_run(dmt);
	if (!ok) {
		trace("dm_task_run failed\n");
		err = -1;
		goto cleanup;
	}

	char *ttype = NULL;
	char *params = NULL;
	dm_get_next_target(dmt, NULL, &target->start, &target->size, &ttype, &params);
	target->ttype = ttype ? strdup(ttype) : NULL;
	target->params = params ? strdup(params) : NULL;

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

	dm_task_set_name(dmt, name);
	int ok =
	    dm_task_add_target(dmt, target->start, target->size, target->ttype, target->params);
	if (!ok) {
		trace("dm_task_add_target failed\n");
		return -1;
	}

	ok = dm_task_run(dmt);
	if (!ok) {
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

int update_device_nodes(const char *name) {
	if (!dm_mknodes(name)) {
		trace("dm_mknodes failed\n");
		return -1;
	}

	dm_task_update_nodes();

	return 0;
}
