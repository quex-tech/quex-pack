// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef ENABLE_TRACE
#define trace(...) printf(__VA_ARGS__)
#else
#define trace(...)
#endif

#define sizeof_field(t, f) (sizeof(((t *)0)->f))
#define sizeof_array(a) (sizeof(a) / sizeof((a)[0]))

int init_socket(uint16_t port);
void write_hex(const uint8_t *bytes, size_t bytes_len, char *out_hex);
int write_hex_to_file(const char *path, const uint8_t *bytes, size_t bytes_len);
int read_hex(const char *hex, uint8_t *out_bytes, size_t bytes_len);
int replace_in_file(const char *path, const char *target, const char *replacement);
int copy_file(const char *src_path, const char *dst_path);
int zeroize_device(const char *dev_path, uint64_t len);

static inline uint16_t read_le16(const void *p) {
	uint16_t v;
	memcpy(&v, p, sizeof v);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return v;
#else
	return __builtin_bswap16(v);
#endif
}

static inline uint32_t read_le32(const void *p) {
	uint32_t v;
	memcpy(&v, p, sizeof v);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return v;
#else
	return __builtin_bswap32(v);
#endif
}

static inline uint64_t read_le64(const void *p) {
	uint64_t v;
	memcpy(&v, p, sizeof v);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return v;
#else
	return __builtin_bswap64(v);
#endif
}

#endif
