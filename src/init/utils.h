// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef ENABLE_TRACE
#include <stdio.h>
#define trace(...) printf(__VA_ARGS__)
#else
#define trace(...)
#endif

#define sizeof_field(t, f) (sizeof(((t *)0)->f))
#define sizeof_array(a) (sizeof(a) / sizeof((a)[0]))

int init_socket(uint16_t port);
void write_hex(const uint8_t *bytes, ptrdiff_t bytes_len, char *out_hex, ptrdiff_t hex_len);
int write_hex_to_file(const char *path, const uint8_t *bytes, ptrdiff_t bytes_len);
int read_hex(const char *hex, uint8_t *out_bytes, ptrdiff_t bytes_len);
int replace_in_file(const char *path, const char *target, const char *replacement);
int copy_file(const char *src_path, const char *dst_path);
int zeroize_device(const char *dev_path, uint64_t len);
int snprintf_checked(char *str, ptrdiff_t size, const char *format, ...);

static inline uint16_t read_u16le(const uint8_t *buf) {
	return (uint16_t)((uint16_t)buf[1] << 8) | (uint16_t)((uint16_t)buf[0] << 0);
}

static inline uint32_t read_u32le(const uint8_t *buf) {
	return (uint32_t)buf[3] << 24 | (uint32_t)buf[2] << 16 | (uint32_t)buf[1] << 8 |
	       (uint32_t)buf[0] << 0;
}

static inline uint64_t read_u64le(const uint8_t *buf) {
	return (uint64_t)buf[7] << 56 | (uint64_t)buf[6] << 48 | (uint64_t)buf[5] << 40 |
	       (uint64_t)buf[4] << 32 | (uint64_t)buf[3] << 24 | (uint64_t)buf[2] << 16 |
	       (uint64_t)buf[1] << 8 | (uint64_t)buf[0] << 0;
}

#endif
