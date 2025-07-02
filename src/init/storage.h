#ifndef _STORAGE_H_
#define _STORAGE_H_

#include <stdint.h>

int setup_storage(const uint8_t secret_key[32], const char *serial, const char *mount_point);

#endif
