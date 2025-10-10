// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _KEY_H_
#define _KEY_H_

#include "tdx.h"
#include <stddef.h>
#include <stdint.h>

int get_sk(uint8_t sk[32], const char *key_request_mask_hex, const char *vault_mr_enclave_hex,
           const char *root_pem_path, const char *quote_path, const struct tdx_iface *tdx,
           int (*f_entropy)(void *, unsigned char *, size_t));

#endif