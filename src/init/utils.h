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

int load_binary(const char *path, void *out_struct, size_t size);
int init_socket(uint16_t port);
void write_hex(uint8_t *bytes, size_t bytes_len, char *dest);
int write_hex_to_file(const char *filename, uint8_t *bytes, size_t bytes_len);
int replace_in_file(const char *filename, const char *target, const char *replacement);

#endif
