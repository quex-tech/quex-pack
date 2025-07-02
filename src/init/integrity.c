#include "integrity.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libdevmapper.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SECTOR_SIZE 512
#define BLOCK_SIZE 512
#define SUPERBLOCK_SIZE 4096
#define JOURNAL_SECTORS 1024
#define SUPERBLOCK_IS_INVALID 1

struct target_params {
	uint64_t size;
	const char *devpath;
	const char *key_hex;
	uint32_t journal_sectors;
	uint32_t block_size;
};

static int add_integrity_target(struct dm_task *dmt, struct target_params *p) {
	char params[512];
	snprintf(params, sizeof(params),
	         "%s 0 - J 5 "
	         "journal_sectors:%u "
	         "internal_hash:hmac(sha256):%s "
	         "block_size:%d "
	         "fix_hmac fix_padding",
	         p->devpath, p->journal_sectors, p->key_hex, p->block_size);

	int ok = dm_task_add_target(dmt, 0, p->size, "integrity", params);
	if (!ok) {
		trace("dm_task_add_target failed\n");
		return -1;
	}

	return 0;
}

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

int create_device(const char *name, struct target_params *params) {
	int err = 0;

	struct dm_task *dmt = dm_task_create(DM_DEVICE_CREATE);
	if (!dmt) {
		trace("dm_task_create failed\n");
		err = -1;
		goto cleanup;
	}

	dm_task_set_name(dmt, name);
	dm_task_set_add_node(dmt, DM_ADD_NODE_ON_CREATE);

	err = add_integrity_target(dmt, params);
	if (err) {
		trace("add_integrity_target failed\n");
		goto cleanup;
	}

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

static int reload_table(const char *name, struct target_params *params) {
	int err = 0;

	struct dm_task *dmt = dm_task_create(DM_DEVICE_RELOAD);
	if (!dmt) {
		err = -1;
		goto cleanup;
	}

	dm_task_set_name(dmt, name);
	err = add_integrity_target(dmt, params);
	if (err) {
		goto cleanup;
	}

	int ok = dm_task_run(dmt);
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

static int get_provided_sectors(const char *name, uint64_t *result) {
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

	uint64_t start, length;
	char *ttype, *params;

	dm_get_next_target(dmt, NULL, &start, &length, &ttype, &params);

	if (!ttype || !params || strcmp(ttype, "integrity")) {
		err = -1;
		goto cleanup;
	}

	uint64_t mismatch, prov;
	if (sscanf(params, "%" PRIu64 " %" PRIu64, &mismatch, &prov) != 2) {
		err = -1;
		goto cleanup;
	}

	*result = prov;

cleanup:
	if (dmt) {
		dm_task_destroy(dmt);
	}
	return err;
}

int validate_superblock(const char *dev_path) {
	int err = 0;
	uint8_t sb[SUPERBLOCK_SIZE];
	int fd = open(dev_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = errno;
		trace("open %s failed: %s\n", dev_path, strerror(err));
		return -err;
	}

	ssize_t n = pread(fd, sb, SUPERBLOCK_SIZE, 0);
	err = errno;
	close(fd);
	if (n != SUPERBLOCK_SIZE) {
		trace("Cannot read superblock from %s: %s\n", dev_path, strerror(err));
		return -err;
	}

	char sb_hex[129] = {0};
	write_hex(sb, 64, sb_hex);
	trace("Superblock: %s\n", sb_hex);

	if (memcmp(sb, "integrt", 8) != 0) {
		trace("Invalid magic\n");
		return SUPERBLOCK_IS_INVALID;
	}

	uint8_t version = sb[8];
	if (version != 5) {
		trace("Invalid version: %d\n", version);
		return SUPERBLOCK_IS_INVALID;
	}

	uint8_t log2_interleave_sectors = sb[9];
	if (log2_interleave_sectors != 0x0f) {
		trace("Invalid log2_interleave_sectors: %d\n", log2_interleave_sectors);
		return SUPERBLOCK_IS_INVALID;
	}

	uint16_t tag_size = le16toh(*(uint16_t *)(sb + 10));
	if (tag_size != 32) {
		trace("Invalid tag size: %d\n", tag_size);
		return SUPERBLOCK_IS_INVALID;
	}

	uint16_t flags = le16toh(*(uint16_t *)(sb + 24));
	if (flags != 0x18) {
		trace("Invalid flags: %d\n", flags);
		return SUPERBLOCK_IS_INVALID;
	}

	uint8_t log2_sectors_per_block = sb[28];
	if (log2_sectors_per_block != 0) {
		trace("Invalid log2_sectors_per_block: %d\n", log2_sectors_per_block);
		return SUPERBLOCK_IS_INVALID;
	}

	uint16_t pad = *(uint16_t *)(sb + 30);
	if (pad != 0) {
		trace("Non-zero pad\n");
		return SUPERBLOCK_IS_INVALID;
	}

	uint64_t pad2 = *(uint64_t *)(sb + 40);
	if (pad2 != 0) {
		trace("Non-zero pad2\n");
		return SUPERBLOCK_IS_INVALID;
	}

	return 0;
}

int setup_integrity(const char *mapper_name, const char *dev_path, const uint8_t key[32]) {
	char key_hex[65];
	write_hex(key, 32, key_hex);

	int validate_superblock_err = validate_superblock(dev_path);
	if (validate_superblock_err && validate_superblock_err != SUPERBLOCK_IS_INVALID) {
		trace("Cannot validate superblock\n");
		return -1;
	}

	if (validate_superblock_err == SUPERBLOCK_IS_INVALID) {
		trace("Superblock is invalid. Zeroizing it...\n");
		if (zeroize_device(dev_path, SUPERBLOCK_SIZE) != 0) {
			trace("zeroize_device %s failed\n", dev_path);
			return -1;
		}
	}

	struct target_params params = {1, dev_path, key_hex, JOURNAL_SECTORS, BLOCK_SIZE};

	int err = create_device(mapper_name, &params);
	if (err) {
		trace("create_device failed\n");
		return -1;
	}

	uint64_t provided = 0;
	err = get_provided_sectors(mapper_name, &provided);
	if (err) {
		trace("get_provided_sectors failed\n");
		return -1;
	}

	err = run_simple_task(mapper_name, DM_DEVICE_SUSPEND);
	if (err) {
		trace("suspend_dm_device failed\n");
		return -1;
	}

	params.size = provided;
	err = reload_table(mapper_name, &params);
	if (err) {
		trace("reload_table failed\n");
		return -1;
	}

	err = run_simple_task(mapper_name, DM_DEVICE_RESUME);
	if (err) {
		trace("resume_dm_device failed\n");
		return -1;
	}

	if (!dm_mknodes(mapper_name)) {
		trace("dm_mknodes failed\n");
		return -1;
	}

	dm_task_update_nodes();

	if (validate_superblock_err == SUPERBLOCK_IS_INVALID) {
		trace("Zeroizing the whole device...\n");
		char mapped_device_path[64];
		snprintf(mapped_device_path, sizeof(mapped_device_path), "/dev/mapper/%s",
		         mapper_name);
		if (zeroize_device(mapped_device_path, provided * SECTOR_SIZE) != 0) {
			trace("zeroize_device %s failed\n", mapped_device_path);
			return -1;
		}
	}

	return 0;
}
