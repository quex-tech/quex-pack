// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _TEST_H_
#define _TEST_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int passed_count;
static int failed_count;

#define must(c, ...)                                                                               \
	if (!(c)) {                                                                                \
		failed_count++;                                                                    \
		printf(__VA_ARGS__);                                                               \
		printf("\n");                                                                      \
	} else {                                                                                   \
		passed_count++;                                                                    \
	}

static int read_bin_file(const char *path, uint8_t **out, size_t *out_len) {
	FILE *f = fopen(path, "rb");
	if (!f) {
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	long sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return -1;
	}
	rewind(f);
	uint8_t *buf = malloc((size_t)sz);
	if (!buf) {
		fclose(f);
		return -1;
	}
	size_t n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	if (n != (size_t)sz) {
		free(buf);
		return -1;
	}
	*out = buf;
	if (out_len) {
		*out_len = (size_t)sz;
	}
	return 0;
}

#endif
