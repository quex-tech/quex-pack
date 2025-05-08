#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdio.h>

#ifdef ENABLE_TRACE
  #define trace(...) printf(__VA_ARGS__)
#else
  #define trace(...)
#endif

int load_binary(const char *path, void *out_struct, size_t size);
int init_socket(uint16_t port);

#endif
