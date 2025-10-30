#include "test_utils.h"
#include <stdio.h>
#include <stdlib.h>

int read_bin_file(const char *path, uint8_t **out, ptrdiff_t *out_len) {
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
	uint8_t *buf = (uint8_t *)malloc((size_t)sz);
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
		*out_len = sz;
	}
	return 0;
}
