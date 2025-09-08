// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "mkfs.h"
#include "utils.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <ext2fs/ext2_fs.h>
#pragma GCC diagnostic pop
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <ext2fs/ext2fs.h>
#pragma GCC diagnostic pop
#include <stdbool.h>
#include <sys/wait.h>
#include <unistd.h>

static bool device_is_ext4(const char *dev) {
	ext2_filsys fs = NULL;
	errcode_t err;

	err = ext2fs_open(dev, 0, 0, 0, unix_io_manager, &fs);
	if (err) {
		return false;
	}

	if (fs->super->s_magic != EXT2_SUPER_MAGIC) {
		ext2fs_close(fs);
		return false;
	}

	bool has_ext4_features = ext2fs_has_feature_extents(fs->super) &&
	                         ext2fs_has_feature_64bit(fs->super) &&
	                         ext2fs_has_feature_metadata_csum(fs->super);

	ext2fs_close(fs);

	return has_ext4_features;
}

static int mkfs_ext4(const char *dev, const char *options) {
	pid_t pid = fork();
	if (pid < 0) {
		int err = errno;
		trace("fork failed: %s\n", strerror(err));
		return -err;
	}

	if (pid == 0) {
		execl("/usr/bin/mke2fs", "mke2fs", "-t", "ext4", "-F", "-q", "-L", "demo-ext4",
		      "-O", options, dev, (char *)NULL);
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

	if (device_is_ext4(spec->dev)) {
		trace("%s already has %s\n", spec->dev, spec->fstype);
		return 0;
	}

	trace("No %s. Formatting...\n", spec->fstype);
	int err = mkfs_ext4(spec->dev, spec->options);
	if (err) {
		trace("mkfs_ext4 failed: %d\n", err);
		return err;
	}

	return 0;
}
