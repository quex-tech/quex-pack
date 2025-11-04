// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef DER_H
#define DER_H

#include <stddef.h>
#include <stdint.h>

int rs_to_der(const uint8_t sig_rs[64], uint8_t *out_der, ptrdiff_t max_der_len,
              ptrdiff_t *out_der_len);
int pub_key_to_der(const uint8_t pub_key[64], uint8_t *out_der, ptrdiff_t max_der_len,
                   ptrdiff_t *out_der_len);

#endif
