// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef INTEGRITY_CRYPT_H
#define INTEGRITY_CRYPT_H

#include <stdint.h>

struct integrity_spec {
	const char *dev;
	const char *name;
};

struct crypt_spec {
	const char *dev;
	const char *name;
};

int parse_integrity_spec(char *input, struct integrity_spec *out_spec);
int setup_integrity(const struct integrity_spec *spec, const uint8_t mac_key[32],
                    const uint8_t journal_crypt_key[32]);
int parse_crypt_spec(char *input, struct crypt_spec *out_spec);
int setup_crypt(const struct crypt_spec *spec, const uint8_t key[32],
                const uint8_t journal_crypt_key[32], const uint8_t journal_mac_key[32]);

#endif
