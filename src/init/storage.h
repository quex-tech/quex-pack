#ifndef _STORAGE_H_
#define _STORAGE_H_

#include <stdint.h>

int setup_storage(const uint8_t sk[32], const char *dev_path, const char *name);

#endif
