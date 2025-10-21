// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "integrity_crypt.h"
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
#define JOURNAL_SECTORS 1024U
#define NO_SUPERBLOCK 1
#define DEV_PATH_MAX_LENGTH 128
#define MAPPER_NAME_MAX_LENGTH 64
#define TABLE_MAX_LENGTH 512

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

static void parse_superblock(const uint8_t buf[SUPERBLOCK_SIZE], struct superblock *sb) {
	memcpy(sb->magic, buf, 8);
	sb->version = buf[8];
	sb->log2_interleave_sectors = buf[9];
	sb->integrity_tag_size = read_le16(buf + 10);
	sb->journal_sections = read_le32(buf + 12);
	sb->provided_data_sectors = read_le64(buf + 16);
	sb->flags = read_le32(buf + 24);
	sb->log2_sectors_per_block = buf[28];
	sb->log2_blocks_per_bitmap_bit = buf[29];
	memcpy(sb->pad, buf + 30, 2);
	sb->recalc_sector = read_le64(buf + 32);
	memcpy(sb->pad2, buf + 40, 8);
	memcpy(sb->salt, buf + 48, 16);
}

static const struct superblock integrity_only_expected_sb = {.magic = "integrt",
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

static const struct superblock integrity_crypt_expected_sb = {.magic = "integrt",
                                                              .version = 5,
                                                              .log2_interleave_sectors = 0x0f,
                                                              .integrity_tag_size = 28,
                                                              .journal_sections = 0,
                                                              .provided_data_sectors = 0,
                                                              .flags = 0x19,
                                                              .log2_sectors_per_block = 0,
                                                              .log2_blocks_per_bitmap_bit = 0,
                                                              .pad = {0},
                                                              .recalc_sector = 0,
                                                              .pad2 = {0},
                                                              .salt = {0}};

static int get_superblock(const char *dev_path, struct superblock *output) {
	uint8_t raw_sb[SUPERBLOCK_SIZE];
	int fd = open(dev_path, O_RDONLY);
	if (fd < 0) {
		int err = errno;
		trace("open %s failed: %s\n", dev_path, strerror(err));
		return -err;
	}

	int flags = fcntl(fd, F_GETFD);
	if (flags >= 0) {
		fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		int err = errno;
		trace("lseek on %s failed: %s\n", dev_path, strerror(err));
		close(fd);
		return -err;
	}

	ssize_t n = read(fd, raw_sb, SUPERBLOCK_SIZE);
	close(fd);

	if (n < 0) {
		int err = errno;
		trace("Cannot read superblock from %s: %s\n", dev_path, strerror(err));
		return -err;
	}

	if (n != SUPERBLOCK_SIZE) {
		trace("Cannot read superblock from %s: read %ld, want %d\n", dev_path, n,
		      SUPERBLOCK_SIZE);
		return -1;
	}

#ifdef ENABLE_TRACE
	char sb_hex[129] = {0};
	write_hex(raw_sb, 64, sb_hex);
	trace("Superblock: %s\n", sb_hex);
#endif

	parse_superblock(raw_sb, output);

	if (memcmp(output->magic, "integrt", 8) != 0) {
		trace("Invalid magic\n");
		return NO_SUPERBLOCK;
	}

	return 0;
}

static int validate_superblock(const struct superblock *sb, const struct superblock *expected_sb) {

	if (memcmp(sb->magic, expected_sb->magic, sizeof expected_sb->magic) != 0) {
		trace("Invalid magic\n");
		return -1;
	}

	if (sb->version != expected_sb->version) {
		trace("Invalid version: %d\n", sb->version);
		return -1;
	}

	if (sb->log2_interleave_sectors != expected_sb->log2_interleave_sectors) {
		trace("Invalid log2_interleave_sectors: %d\n", sb->log2_interleave_sectors);
		return -1;
	}

	if (sb->integrity_tag_size != expected_sb->integrity_tag_size) {
		trace("Invalid tag size: %d\n", sb->integrity_tag_size);
		return -1;
	}

	if (sb->flags != expected_sb->flags) {
		trace("Invalid flags: %u\n", sb->flags);
		return -1;
	}

	if (sb->log2_sectors_per_block != expected_sb->log2_sectors_per_block) {
		trace("Invalid log2_sectors_per_block: %d\n", sb->log2_sectors_per_block);
		return -1;
	}

	if (memcmp(sb->pad, expected_sb->pad, sizeof expected_sb->pad) != 0) {
		trace("Non-zero pad\n");
		return -1;
	}

	if (memcmp(sb->pad2, expected_sb->pad2, sizeof expected_sb->pad2) != 0) {
		trace("Non-zero pad2\n");
		return -1;
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
	free(target.ttype);
	free(target.params);
	return err;
}

static int test_read(const char *dev_path) {
	int fd = open(dev_path, O_RDONLY);
	if (fd < 0) {
		trace("Cannot open %s: %s\n", dev_path, strerror(errno));
		return -1;
	}

	int flags = fcntl(fd, F_GETFD);
	if (flags >= 0) {
		fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
	}

	char buffer[4096];
	ssize_t bytes_read = read(fd, buffer, sizeof buffer);
	int read_errno = errno;
	close(fd);

	if (bytes_read == sizeof buffer) {
		return 0;
	}

	if (bytes_read < 0) {
		trace("Cannot read from %s: %s\n", dev_path, strerror(read_errno));
		return -read_errno;
	}

	return -1;
}

static void format_integrity_only_params(const char *dev_path, const uint8_t mac_key[32],
                                         const uint8_t journal_crypt_key[32],
                                         char output[TABLE_MAX_LENGTH]) {
	char mac_key_hex[65];
	write_hex(mac_key, 32, mac_key_hex);

	char journal_crypt_key_hex[65];
	write_hex(journal_crypt_key, 32, journal_crypt_key_hex);

	snprintf(output, TABLE_MAX_LENGTH,
	         "%s 0 - J 6 "
	         "journal_sectors:%u "
	         "internal_hash:hmac(sha256):%s "
	         "journal_crypt:ctr(aes):%s "
	         "block_size:%d "
	         "fix_hmac fix_padding",
	         dev_path, JOURNAL_SECTORS, mac_key_hex, journal_crypt_key_hex, BLOCK_SIZE);
}

static void format_integrity_crypt_params(const char *dev_path, const uint8_t journal_crypt_key[32],
                                          const uint8_t journal_mac_key[32],
                                          char output[TABLE_MAX_LENGTH]) {

	char journal_crypt_key_hex[65];
	write_hex(journal_crypt_key, 32, journal_crypt_key_hex);

	char journal_mac_key_hex[65];
	write_hex(journal_mac_key, 32, journal_mac_key_hex);

	snprintf(output, TABLE_MAX_LENGTH,
	         "%s 0 28 J 6 "
	         "journal_sectors:%u "
	         "journal_crypt:ctr(aes):%s "
	         "journal_mac:hmac(sha256):%s "
	         "block_size:%d "
	         "fix_hmac fix_padding",
	         dev_path, JOURNAL_SECTORS, journal_crypt_key_hex, journal_mac_key_hex, BLOCK_SIZE);
}

static void format_crypt_params(const char *dev_path, const uint8_t key[32],
                                char output[TABLE_MAX_LENGTH]) {
	char key_hex[65];
	write_hex(key, 32, key_hex);

	snprintf(output, TABLE_MAX_LENGTH,
	         "capi:gcm(aes)-random %s 0 %s 0 "
	         "2 integrity:28:aead sector_size:%d",
	         key_hex, dev_path, BLOCK_SIZE);
}

static int map_integrity_device(const char *mapper_name, char target_params[TABLE_MAX_LENGTH]) {
	char ttype[] = "integrity";
	struct dm_target target = {0, 1, ttype, target_params};

	int err = create_device(mapper_name, &target);
	if (err) {
		trace("create_device failed\n");
		return err;
	}

	uint64_t provided = 0;
	err = get_provided_sectors(mapper_name, &provided);
	if (err) {
		trace("get_provided_sectors failed\n");
		return err;
	}

	err = suspend_device(mapper_name);
	if (err) {
		trace("suspend_device failed\n");
		return err;
	}

	target.size = provided;
	err = reload_table(mapper_name, &target);
	if (err) {
		trace("reload_table failed\n");
		return err;
	}

	err = resume_device(mapper_name);
	if (err) {
		trace("resume_device failed\n");
		return err;
	}

	err = update_device_nodes();
	if (err) {
		trace("update_device_nodes failed\n");
		return err;
	}

	return 0;
}

static int map_crypt_device(const char *mapper_name, char target_params[TABLE_MAX_LENGTH],
                            uint64_t provided_sectors) {
	char ttype[] = "crypt";
	struct dm_target target = {0, provided_sectors, ttype, target_params};

	int err = create_device(mapper_name, &target);
	if (err) {
		trace("create_device failed\n");
		return err;
	}

	err = update_device_nodes();
	if (err) {
		trace("update_device_nodes failed\n");
		return err;
	}

	return 0;
}

static int init_integrity(const char *mapper_name, const char *dev_path, const uint8_t mac_key[32],
                          const uint8_t journal_crypt_key[32]) {
	trace("Initializing integrity...\n");

	if (zeroize_device(dev_path, SUPERBLOCK_SIZE) != 0) {
		trace("zeroize_device %s failed\n", dev_path);
		return -1;
	}

	char target_params[TABLE_MAX_LENGTH] = {0};
	format_integrity_only_params(dev_path, mac_key, journal_crypt_key, target_params);

	int err = map_integrity_device(mapper_name, target_params);
	if (err) {
		trace("map_integrity_device failed\n");
		return err;
	}

	trace("Zeroizing the whole device...\n");

	uint64_t provided = 0;
	err = get_provided_sectors(mapper_name, &provided);
	if (err) {
		trace("get_provided_sectors failed\n");
		return err;
	}

	char mapped_dev_path[DEV_PATH_MAX_LENGTH];
	snprintf(mapped_dev_path, sizeof mapped_dev_path, "/dev/mapper/%s", mapper_name);

	if (zeroize_device(mapped_dev_path, provided * SECTOR_SIZE) != 0) {
		trace("zeroize_device %s failed\n", mapped_dev_path);
		return err;
	}

	return 0;
}

static int restore_integrity(const char *mapper_name, const char *dev_path,
                             const uint8_t mac_key[32], const uint8_t journal_crypt_key[32]) {
	trace("Restoring integrity...\n");

	char target_params[TABLE_MAX_LENGTH] = {0};
	format_integrity_only_params(dev_path, mac_key, journal_crypt_key, target_params);

	int err = map_integrity_device(mapper_name, target_params);
	if (err) {
		trace("map_integrity_device failed\n");
		return err;
	}

	char mapped_dev_path[DEV_PATH_MAX_LENGTH];
	snprintf(mapped_dev_path, sizeof mapped_dev_path, "/dev/mapper/%s", mapper_name);

	err = test_read(mapped_dev_path);
	if (err) {
		trace("Read test failed: %d\n", err);
		return err;
	}

	return 0;
}

static int init_crypt(const char *mapper_name, const char *dev_path, const uint8_t key[32],
                      const uint8_t journal_crypt_key[32], const uint8_t journal_mac_key[32]) {
	trace("Initializing integrity...\n");

	char integrity_mapper_name[MAPPER_NAME_MAX_LENGTH] = {0};
	snprintf(integrity_mapper_name, sizeof integrity_mapper_name, "%s-integrity", mapper_name);

	if (zeroize_device(dev_path, SUPERBLOCK_SIZE) != 0) {
		trace("zeroize_device %s failed\n", dev_path);
		return -1;
	}

	char integrity_target_params[TABLE_MAX_LENGTH] = {0};
	format_integrity_crypt_params(dev_path, journal_crypt_key, journal_mac_key,
	                              integrity_target_params);

	int err = map_integrity_device(integrity_mapper_name, integrity_target_params);
	if (err) {
		trace("map_integrity_device failed\n");
		return err;
	}

	trace("Initializing crypt...\n");

	uint64_t provided = 0;
	err = get_provided_sectors(integrity_mapper_name, &provided);
	if (err) {
		trace("get_provided_sectors failed\n");
		return err;
	}

	char mapped_integrity_dev_path[DEV_PATH_MAX_LENGTH];
	snprintf(mapped_integrity_dev_path, sizeof mapped_integrity_dev_path, "/dev/mapper/%s",
	         integrity_mapper_name);

	char crypt_target_params[TABLE_MAX_LENGTH] = {0};
	format_crypt_params(mapped_integrity_dev_path, key, crypt_target_params);

	err = map_crypt_device(mapper_name, crypt_target_params, provided);
	if (err) {
		trace("map_crypt_device failed\n");
		return err;
	}

	trace("Zeroizing the whole device...\n");

	char mapped_dev_path[DEV_PATH_MAX_LENGTH];
	snprintf(mapped_dev_path, sizeof mapped_dev_path, "/dev/mapper/%s", mapper_name);

	if (zeroize_device(mapped_dev_path, provided * SECTOR_SIZE) != 0) {
		trace("zeroize_device %s failed\n", mapped_dev_path);
		return -1;
	}

	return 0;
}

static int restore_crypt(const char *mapper_name, const char *dev_path, const uint8_t key[32],
                         const uint8_t journal_crypt_key[32], const uint8_t journal_mac_key[32]) {
	trace("Restoring integrity...\n");

	char integrity_mapper_name[MAPPER_NAME_MAX_LENGTH] = {0};
	snprintf(integrity_mapper_name, sizeof integrity_mapper_name, "%s-integrity", mapper_name);

	char integrity_target_params[TABLE_MAX_LENGTH] = {0};
	format_integrity_crypt_params(dev_path, journal_crypt_key, journal_mac_key,
	                              integrity_target_params);

	int err = map_integrity_device(integrity_mapper_name, integrity_target_params);
	if (err) {
		trace("map_integrity_device failed\n");
		return err;
	}

	trace("Restoring crypt...\n");

	char mapped_integrity_dev_path[DEV_PATH_MAX_LENGTH];
	snprintf(mapped_integrity_dev_path, sizeof mapped_integrity_dev_path, "/dev/mapper/%s",
	         integrity_mapper_name);

	char crypt_target_params[TABLE_MAX_LENGTH] = {0};
	format_crypt_params(mapped_integrity_dev_path, key, crypt_target_params);

	uint64_t provided = 0;
	err = get_provided_sectors(integrity_mapper_name, &provided);
	if (err) {
		trace("get_provided_sectors failed\n");
		return err;
	}

	err = map_crypt_device(mapper_name, crypt_target_params, provided);
	if (err) {
		trace("map_crypt_device failed\n");
		return err;
	}

	char mapped_dev_path[DEV_PATH_MAX_LENGTH];
	snprintf(mapped_dev_path, sizeof mapped_dev_path, "/dev/mapper/%s", mapper_name);

	err = test_read(mapped_dev_path);
	if (err) {
		trace("Read test failed: %d\n", err);
		return err;
	}

	return 0;
}

int parse_integrity_spec(char *input, struct integrity_spec *out_spec) {
	if (!input || !out_spec) {
		return -1;
	}

	char *saveptr;
	char *dev = strtok_r(input, ":", &saveptr);
	char *name = strtok_r(NULL, ":", &saveptr);

	if (!dev || !name) {
		trace("Invalid integrity format: %s\n", input);
		return -1;
	}

	out_spec->dev = dev;
	out_spec->name = name;

	return 0;
}

int setup_integrity(const struct integrity_spec *spec, const uint8_t mac_key[32],
                    const uint8_t journal_crypt_key[32]) {
	struct superblock sb = {0};
	int err = get_superblock(spec->dev, &sb);
	if (err && err != NO_SUPERBLOCK) {
		trace("Cannot get superblock\n");
		return err;
	}

	if (err == NO_SUPERBLOCK) {
		trace("No superblock. Zeroizing it...\n");
		return init_integrity(spec->name, spec->dev, mac_key, journal_crypt_key);
	}

	err = validate_superblock(&sb, &integrity_only_expected_sb);
	if (err) {
		trace("Invalid superblock\n");
		return err;
	}

	return restore_integrity(spec->name, spec->dev, mac_key, journal_crypt_key);
}

int parse_crypt_spec(char *input, struct crypt_spec *out_spec) {
	if (!input || !out_spec) {
		return -1;
	}

	char *saveptr;
	char *dev = strtok_r(input, ":", &saveptr);
	char *name = strtok_r(NULL, ":", &saveptr);

	if (!dev || !name) {
		trace("Invalid crypt format: %s\n", input);
		return -1;
	}

	out_spec->dev = dev;
	out_spec->name = name;

	return 0;
}

int setup_crypt(const struct crypt_spec *spec, const uint8_t key[32],
                const uint8_t journal_crypt_key[32], const uint8_t journal_mac_key[32]) {
	struct superblock sb = {0};
	int err = get_superblock(spec->dev, &sb);
	if (err && err != NO_SUPERBLOCK) {
		trace("Cannot get superblock\n");
		return err;
	}

	if (err == NO_SUPERBLOCK) {
		trace("No superblock. Zeroizing it...\n");
		return init_crypt(spec->name, spec->dev, key, journal_crypt_key, journal_mac_key);
	}

	err = validate_superblock(&sb, &integrity_crypt_expected_sb);
	if (err) {
		trace("Invalid superblock\n");
		return err;
	}

	return restore_crypt(spec->name, spec->dev, key, journal_crypt_key, journal_mac_key);
}
