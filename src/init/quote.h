// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef QUOTE_H
#define QUOTE_H

#include <mbedtls/x509_crt.h>
#include <sgx_quote_3.h>
#include <stdbool.h>
#include <stddef.h>

bool is_quote_header_well_formed(const sgx_quote3_t *quote);
int verify_quote(const sgx_quote3_t *quote, ptrdiff_t quote_len, mbedtls_x509_crt *root_crt);

#endif
