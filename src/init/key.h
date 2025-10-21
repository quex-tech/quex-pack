// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _KEY_H_
#define _KEY_H_

#include <stddef.h>
#include <stdint.h>

int get_keys(const char *key_request_mask_hex, const char *vault_mr_enclave_hex,
             const char *root_pem_path, int (*f_entropy)(void *, uint8_t *, size_t),
             uint8_t out_sk[static 32], uint8_t out_pk[static 64]);

#endif
