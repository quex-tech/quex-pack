#ifndef _INTEGRITY_H_
#define _INTEGRITY_H_

#include <stdint.h>

int setup_integrity(const char *mapper_name, const char *dev_path, const uint8_t key[32]);

#endif
