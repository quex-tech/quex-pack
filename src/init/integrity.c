#include "integrity.h"
#include "dm.h"
#include "utils.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SECTOR_SIZE 512
#define BLOCK_SIZE 512
#define SUPERBLOCK_SIZE 4096
#define JOURNAL_SECTORS 1024
#define SUPERBLOCK_IS_INVALID 1

struct superblock {
	uint8_t magic[8];
	uint8_t version;
	uint8_t log2_interleave_sectors;
	uint16_t integrity_tag_size;
	uint32_t journal_sections;
	uint64_t provided_data_sectors;
	uint32_t flags;
	uint8_t log2_sectors_per_block;
	uint8_t log2_blocks_per_bitmap_bit;
	uint8_t pad[2];
	uint64_t recalc_sector;
	uint8_t pad2[8];
	uint8_t salt[16];
};

static void parse_superblock(uint8_t buf[SUPERBLOCK_SIZE], struct superblock *sb) {
	memcpy(sb->magic, buf, 8);
	sb->version = buf[8];
	sb->log2_interleave_sectors = buf[9];
	sb->integrity_tag_size = le16toh(*(uint16_t *)(buf + 10));
	sb->journal_sections = le32toh(*(uint32_t *)(buf + 12));
	sb->provided_data_sectors = le64toh(*(uint16_t *)(buf + 16));
	sb->flags = le32toh(*(uint32_t *)(buf + 24));
	sb->log2_sectors_per_block = buf[28];
	sb->log2_blocks_per_bitmap_bit = buf[29];
	memcpy(sb->pad, buf + 30, 2);
	sb->recalc_sector = le64toh(*(uint64_t *)(buf + 32));
	memcpy(sb->pad2, buf + 40, 8);
	memcpy(sb->salt, buf + 48, 16);
}

static const struct superblock expected_sb = {.magic = "integrt",
                                              .version = 5,
                                              .log2_interleave_sectors = 0x0f,
                                              .integrity_tag_size = 32,
                                              .journal_sections = 0,
                                              .provided_data_sectors = 0,
                                              .flags = 0x18,
                                              .log2_sectors_per_block = 0,
                                              .log2_blocks_per_bitmap_bit = 0,
                                              .pad = {0},
                                              .recalc_sector = 0,
                                              .pad2 = {0},
                                              .salt = {0}};

static int validate_superblock(const char *dev_path) {
	int err = 0;
	uint8_t raw_sb[SUPERBLOCK_SIZE];
	int fd = open(dev_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = errno;
		trace("open %s failed: %s\n", dev_path, strerror(err));
		return -err;
	}

	ssize_t n = pread(fd, raw_sb, SUPERBLOCK_SIZE, 0);
	err = errno;
	close(fd);
	if (n != SUPERBLOCK_SIZE) {
		trace("Cannot read superblock from %s: %s\n", dev_path, strerror(err));
		return -err;
	}

#ifdef ENABLE_TRACE
	char sb_hex[129] = {0};
	write_hex(raw_sb, 64, sb_hex);
	trace("Superblock: %s\n", sb_hex);
#endif

	struct superblock sb = {0};
	parse_superblock(raw_sb, &sb);

	if (memcmp(sb.magic, expected_sb.magic, sizeof(expected_sb.magic)) != 0) {
		trace("Invalid magic\n");
		return SUPERBLOCK_IS_INVALID;
	}

	if (sb.version != expected_sb.version) {
		trace("Invalid version: %d\n", sb.version);
		return SUPERBLOCK_IS_INVALID;
	}

	if (sb.log2_interleave_sectors != expected_sb.log2_interleave_sectors) {
		trace("Invalid log2_interleave_sectors: %d\n", sb.log2_interleave_sectors);
		return SUPERBLOCK_IS_INVALID;
	}

	if (sb.integrity_tag_size != expected_sb.integrity_tag_size) {
		trace("Invalid tag size: %d\n", sb.integrity_tag_size);
		return SUPERBLOCK_IS_INVALID;
	}

	if (sb.flags != expected_sb.flags) {
		trace("Invalid flags: %d\n", sb.flags);
		return SUPERBLOCK_IS_INVALID;
	}

	if (sb.log2_sectors_per_block != expected_sb.log2_sectors_per_block) {
		trace("Invalid log2_sectors_per_block: %d\n", sb.log2_sectors_per_block);
		return SUPERBLOCK_IS_INVALID;
	}

	if (memcmp(sb.pad, expected_sb.pad, sizeof(expected_sb.pad)) != 0) {
		trace("Non-zero pad\n");
		return SUPERBLOCK_IS_INVALID;
	}

	if (memcmp(sb.pad2, expected_sb.pad2, sizeof(expected_sb.pad2)) != 0) {
		trace("Non-zero pad2\n");
		return SUPERBLOCK_IS_INVALID;
	}

	return 0;
}

static int get_provided_sectors(const char *name, uint64_t *result) {
	int err = 0;

	struct dm_target target = {0};
	err = get_device_status(name, &target);
	if (err) {
		trace("get_device_status failed\n");
		goto cleanup;
	}

	if (!target.ttype || !target.params || strcmp(target.ttype, "integrity")) {
		trace("invalid device status: ttype=%s params=%s\n", target.ttype, target.params);
		err = -1;
		goto cleanup;
	}

	uint64_t mismatch, prov;
	if (sscanf(target.params, "%" PRIu64 " %" PRIu64, &mismatch, &prov) != 2) {
		err = -1;
		goto cleanup;
	}

	*result = prov;
cleanup:
	if (target.ttype) {
		free(target.ttype);
	}
	if (target.params) {
		free(target.params);
	}
	return err;
}

int test_read(const char *dev_path) {
	int fd = open(dev_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		trace("Cannot open %s: %s\n", dev_path, strerror(errno));
		return -1;
	}

	char buffer[4096];
	ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
	int read_errno = errno;
	close(fd);

	if (bytes_read == sizeof(buffer)) {
		return 0;
	}

	if (bytes_read < 0) {
		trace("Cannot read from %s: %s\n", dev_path, strerror(read_errno));
		return -read_errno;
	}

	return -1;
}

static int map_device(const char *mapper_name, const char *dev_path, const uint8_t key[32]) {
	char key_hex[65];
	write_hex(key, 32, key_hex);

	char target_params[512] = {0};
	snprintf(target_params, sizeof(target_params),
	         "%s 0 - J 5 "
	         "journal_sectors:%u "
	         "internal_hash:hmac(sha256):%s "
	         "block_size:%d "
	         "fix_hmac fix_padding",
	         dev_path, JOURNAL_SECTORS, key_hex, BLOCK_SIZE);

	struct dm_target target = {0, 1, "integrity", target_params};

	int err = create_device(mapper_name, &target);
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

	err = suspend_device(mapper_name);
	if (err) {
		trace("suspend_device failed\n");
		return -1;
	}

	target.size = provided;
	err = reload_table(mapper_name, &target);
	if (err) {
		trace("reload_table failed\n");
		return -1;
	}

	err = resume_device(mapper_name);
	if (err) {
		trace("resume_dm_device failed\n");
		return -1;
	}

	err = update_device_nodes(mapper_name);
	if (err) {
		trace("update_device_nodes failed\n");
		return -1;
	}

	return 0;
}

static int init_integrity(const char *mapper_name, const char *dev_path, const uint8_t key[32]) {
	trace("Initializing integrity...\n");

	if (zeroize_device(dev_path, SUPERBLOCK_SIZE) != 0) {
		trace("zeroize_device %s failed\n", dev_path);
		return -1;
	}

	int err = map_device(mapper_name, dev_path, key);
	if (err) {
		trace("map_device failed\n");
		return -1;
	}

	trace("Zeroizing the whole device...\n");

	uint64_t provided = 0;
	err = get_provided_sectors(mapper_name, &provided);
	if (err) {
		trace("get_provided_sectors failed\n");
		return -1;
	}

	char mapped_dev_path[64];
	snprintf(mapped_dev_path, sizeof(mapped_dev_path), "/dev/mapper/%s", mapper_name);

	if (zeroize_device(mapped_dev_path, provided * SECTOR_SIZE) != 0) {
		trace("zeroize_device %s failed\n", mapped_dev_path);
		return -1;
	}

	return 0;
}

static int restore_integrity(const char *mapper_name, const char *dev_path, const uint8_t key[32]) {
	trace("Restoring integrity...\n");

	int err = map_device(mapper_name, dev_path, key);
	if (err) {
		trace("map_device failed\n");
		return -1;
	}

	char mapped_dev_path[64];
	snprintf(mapped_dev_path, sizeof(mapped_dev_path), "/dev/mapper/%s", mapper_name);

	err = test_read(mapped_dev_path);
	if (err) {
		trace("Read test failed: %d\n", err);

		err = remove_device(mapper_name);
		if (err) {
			trace("remove_device failed: %d\n", err);
			return -1;
		}

		return init_integrity(mapper_name, dev_path, key);
	}

	return 0;
}

static int setup_integrity_inner(const char *mapper_name, const char *dev_path,
                                 const uint8_t key[32]) {
	int validate_superblock_err = validate_superblock(dev_path);
	if (validate_superblock_err && validate_superblock_err != SUPERBLOCK_IS_INVALID) {
		trace("Cannot validate superblock\n");
		return -1;
	}

	if (validate_superblock_err == SUPERBLOCK_IS_INVALID) {
		trace("Superblock is invalid. Zeroizing it...\n");
		return init_integrity(mapper_name, dev_path, key);
	}

	return restore_integrity(mapper_name, dev_path, key);
}

int parse_integrity_spec(char *input, struct integrity_spec *output) {
	if (!input || !output) {
		return -1;
	}

	char *dev = strtok(input, ":");
	char *name = strtok(NULL, ":");

	if (!dev || !name) {
		trace("Invalid integrity format: %s\n", input);
		return -1;
	}

	output->dev = dev;
	output->name = name;

	return 0;
}

int setup_integrity(struct integrity_spec *spec, const uint8_t key[32]) {
	return setup_integrity_inner(spec->name, spec->dev, key);
}