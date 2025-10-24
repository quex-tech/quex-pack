#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stddef.h>
#include <stdint.h>

int read_bin_file(const char *path, uint8_t **out, size_t *out_len);

#endif
