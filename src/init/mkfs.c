// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "mkfs.h"
#include "utils.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXT4_SUPERBLOCK_OFFSET 1024
#define EXT4_SUPERBLOCK_SIZE 1024

struct superblock {
	uint16_t magic;
};

static void parse_superblock(uint8_t buf[EXT4_SUPERBLOCK_SIZE], struct superblock *sb) {
	sb->magic = le16toh(*(uint16_t *)(buf + 0x38));
}

static int get_superblock(const char *dev_path, struct superblock *output) {
	int err = 0;
	uint8_t raw_sb[EXT4_SUPERBLOCK_SIZE];
	int fd = open(dev_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = errno;
		trace("open %s failed: %s\n", dev_path, strerror(err));
		return -err;
	}

	ssize_t n = pread(fd, raw_sb, EXT4_SUPERBLOCK_SIZE, EXT4_SUPERBLOCK_OFFSET);
	close(fd);

	if (n < 0) {
		err = errno;
		trace("Cannot read superblock from %s: %s\n", dev_path, strerror(err));
		return -err;
	}

	if (n != EXT4_SUPERBLOCK_SIZE) {
		trace("Cannot read superblock from %s: read %ld, want %d\n", dev_path, n,
		      EXT4_SUPERBLOCK_SIZE);
		return -1;
	}

	parse_superblock(raw_sb, output);

	return 0;
}

static int mkfs_ext4(const char *dev, const char *options) {
	pid_t pid = fork();
	if (pid < 0) {
		int err = errno;
		trace("fork failed: %s\n", strerror(err));
		return -err;
	}

	if (pid == 0) {
		execl("/usr/bin/mke2fs", "mke2fs", "-t", "ext4", "-F", "-q", "-L", "quex", "-O",
		      options, dev, (char *)NULL);
		trace("exec failed: %s\n", strerror(errno));
		_exit(127);
	}

	int status;
	if (waitpid(pid, &status, 0) < 0) {
		int err = errno;
		trace("waitpid failed: %s\n", strerror(err));
		return -err;
	}

	trace("mke2fs exit status: %d\n", status);

	return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

int parse_mkfs_spec(char *input, struct mkfs_spec *output) {
	if (!input || !output) {
		return -1;
	}

	char *dev = strtok(input, ":");
	char *fstype = strtok(NULL, ":");
	char *options = strtok(NULL, ":");

	if (!dev || !fstype) {
		trace("Invalid mkfs format: %s\n", input);
		return -1;
	}

	output->dev = dev;
	output->fstype = fstype;
	output->options = options;

	return 0;
}

int mkfs(struct mkfs_spec *spec) {
	if (strcmp(spec->fstype, "ext4") != 0) {
		trace("%s is not supported\n", spec->fstype);
		return -1;
	}

	struct superblock sb = {0};
	int err = get_superblock(spec->dev, &sb);
	if (err) {
		trace("get_superblock failed: %d\n", err);
		return err;
	}

	if (sb.magic == 0xef53) {
		trace("%s already has %s\n", spec->dev, spec->fstype);
		return 0;
	}

	trace("No %s. Formatting...\n", spec->fstype);
	err = mkfs_ext4(spec->dev, spec->options);
	if (err) {
		trace("mkfs_ext4 failed: %d\n", err);
		return err;
	}

	return 0;
}
