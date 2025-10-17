// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "mkfs.h"
#include "utils.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXT4_SUPERBLOCK_OFFSET 1024
#define EXT4_SUPERBLOCK_SIZE 1024

struct superblock {
	uint16_t magic;
};

static void parse_superblock(const uint8_t buf[const EXT4_SUPERBLOCK_SIZE],
                             struct superblock *out_sb) {
	out_sb->magic = read_le16(buf + 0x38);
}

static int get_superblock(const char *dev_path, struct superblock *out_sb) {
	int err;
	uint8_t raw_sb[EXT4_SUPERBLOCK_SIZE];
	int fd = open(dev_path, O_RDONLY);
	if (fd < 0) {
		err = errno;
		trace("open %s failed: %s\n", dev_path, strerror(err));
		return -err;
	}

	int flags = fcntl(fd, F_GETFD);
	if (flags >= 0) {
		fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
	}

	if (lseek(fd, EXT4_SUPERBLOCK_OFFSET, SEEK_SET) < 0) {
		err = errno;
		trace("lseek(%s, %ld) failed: %s\n", dev_path, (long)EXT4_SUPERBLOCK_OFFSET,
		      strerror(err));
		close(fd);
		return -err;
	}

	ssize_t n = read(fd, raw_sb, EXT4_SUPERBLOCK_SIZE);
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

	parse_superblock(raw_sb, out_sb);

	return 0;
}

static int mkfs_ext4(const char *dev, const char *options) {
	int err = 0;
	char arg0[] = "mke2fs";
	char arg1[] = "-t";
	char arg2[] = "ext4";
	char arg3[] = "-F";
	char arg4[] = "-q";
	char arg5[] = "-L";
	char arg6[] = "quex";
	char arg7[] = "-O";
	char *arg8 = NULL;
	char *arg9 = NULL;
	arg8 = strdup(options);
	if (!arg8) {
		trace("strdup failed\n");
		err = -1;
		goto cleanup;
	}
	arg9 = strdup(dev);
	if (!arg9) {
		trace("strdup failed\n");
		err = -1;
		goto cleanup;
	}
	char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, NULL};
	char *envp[] = {NULL};

	pid_t pid;
	int spawn_ret = posix_spawn(&pid, "/usr/bin/mke2fs", NULL, NULL, argv, envp);
	if (spawn_ret != 0) {
		trace("posix_spawn failed: %s\n", strerror(spawn_ret));
		err = -spawn_ret;
		goto cleanup;
	}

	int status;
	pid_t waitpid_ret = waitpid(pid, &status, 0);
	if (waitpid_ret < 0) {
		int waitpid_errno = errno;
		trace("waitpid failed: %s\n", strerror(waitpid_errno));
		err = -waitpid_errno;
		goto cleanup;
	}

	trace("mke2fs exit status: %d\n", status);
	err = (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
cleanup:
	if (arg8) {
		free(arg8);
	}
	if (arg9) {
		free(arg9);
	}

	return err;
}

int parse_mkfs_spec(char *input, struct mkfs_spec *out_spec) {
	if (!input || !out_spec) {
		return -1;
	}

	char *saveptr;
	char *dev = strtok_r(input, ":", &saveptr);
	char *fstype = strtok_r(NULL, ":", &saveptr);
	char *options = strtok_r(NULL, ":", &saveptr);

	if (!dev || !fstype) {
		trace("Invalid mkfs format: %s\n", input);
		return -1;
	}

	out_spec->dev = dev;
	out_spec->fstype = fstype;
	out_spec->options = options;

	return 0;
}

int mkfs(const struct mkfs_spec *spec) {
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
