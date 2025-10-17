// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "mount.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

static unsigned long parse_mount_flags(const char *options_str) {
	unsigned long flags = 0;

	char *options = strdup(options_str);
	if (!options) {
		return 0;
	}

	char *saveptr;
	const char *token = strtok_r(options, ",", &saveptr);
	while (token) {
		if (strcmp(token, "ro") == 0) {
			flags |= MS_RDONLY;
		} else if (strcmp(token, "rw") == 0) {
			flags &= ~(unsigned long)MS_RDONLY;
		} else if (strcmp(token, "nosuid") == 0) {
			flags |= MS_NOSUID;
		} else if (strcmp(token, "nodev") == 0) {
			flags |= MS_NODEV;
		} else if (strcmp(token, "noexec") == 0) {
			flags |= MS_NOEXEC;
		} else if (strcmp(token, "sync") == 0) {
			flags |= MS_SYNCHRONOUS;
		} else if (strcmp(token, "dirsync") == 0) {
			flags |= MS_DIRSYNC;
		} else if (strcmp(token, "mand") == 0) {
			flags |= MS_MANDLOCK;
		} else if (strcmp(token, "noatime") == 0) {
			flags |= MS_NOATIME;
		} else if (strcmp(token, "nodiratime") == 0) {
			flags |= MS_NODIRATIME;
		} else if (strcmp(token, "relatime") == 0) {
			flags |= MS_RELATIME;
		} else if (strcmp(token, "strictatime") == 0) {
			flags |= MS_STRICTATIME;
		} else if (strcmp(token, "lazytime") == 0) {
			flags |= MS_LAZYTIME;
		}
		token = strtok_r(NULL, ",", &saveptr);
	}

	free(options);
	return flags;
}

int parse_mount_spec(char *input, struct mount_spec *out_spec) {
	if (!input || !out_spec) {
		return -1;
	}

	char *saveptr;
	char *source = strtok_r(input, ":", &saveptr);
	char *target = strtok_r(NULL, ":", &saveptr);
	char *fstype = strtok_r(NULL, ":", &saveptr);
	const char *options = strtok_r(NULL, ":", &saveptr);

	if (!source || !target || !fstype) {
		trace("Invalid mount format: %s\n", input);
		return -1;
	}

	out_spec->source = source;
	out_spec->target = target;
	out_spec->fstype = fstype;
	out_spec->flags = options ? parse_mount_flags(options) : 0;

	return 0;
}
