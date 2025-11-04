// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "test_utils.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int read_bin_file(const char *path, uint8_t **out, ptrdiff_t *out_len) {
	FILE *file = fopen(path, "rb");
	if (!file) {
		return -1;
	}
	if (fseek(file, 0, SEEK_END) != 0) {
		(void)fclose(file);
		return -1;
	}
	long size = ftell(file);
	if (size < 0) {
		(void)fclose(file);
		return -1;
	}
	if (fseek(file, 0, SEEK_SET) != 0) {
		(void)fclose(file);
		return -1;
	}
	uint8_t *buf = (uint8_t *)malloc((size_t)size);
	if (!buf) {
		(void)fclose(file);
		return -1;
	}

	size_t nread = fread(buf, 1, (size_t)size, file);
	int err = fclose(file);
	if (err) {
		free(buf);
		return -1;
	}

	if (nread != (size_t)size) {
		free(buf);
		return -1;
	}
	*out = buf;
	if (out_len) {
		*out_len = size;
	}
	return 0;
}
