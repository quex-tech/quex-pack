// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef DER_H
#define DER_H

#include <stddef.h>
#include <stdint.h>

int rs_to_der(const uint8_t rs[static 64], uint8_t *out_der, size_t max_der_len,
              size_t *out_der_len);
int pk_to_der(const uint8_t pk[static 64], uint8_t *out_der, size_t max_der_len,
              size_t *out_der_len);

#endif
