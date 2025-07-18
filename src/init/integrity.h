#ifndef _INTEGRITY_H_
#define _INTEGRITY_H_

#include <stdint.h>

struct integrity_spec {
	const char *dev;
	const char *name;
};

int parse_integrity_spec(char *input, struct integrity_spec *output);
int setup_integrity(struct integrity_spec *spec, const uint8_t key[32]);

#endif
