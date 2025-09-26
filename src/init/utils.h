// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef ENABLE_TRACE
#define trace(...) printf(__VA_ARGS__)
#else
#define trace(...)
#endif

#define sizeof_field(t, f) (sizeof(((t*)0)->f))

int init_socket(uint16_t port);
void write_hex(const uint8_t *bytes, size_t bytes_len, char *dest);
int write_hex_to_file(const char *filename, uint8_t *bytes, size_t bytes_len);
int read_hex(const char *hex, uint8_t *dest, size_t dest_len);
int replace_in_file(const char *filename, const char *target, const char *replacement);
int copy_file(const char *src_path, const char *dst_path);
int zeroize_device(const char *dev_path, uint64_t len);

#endif
