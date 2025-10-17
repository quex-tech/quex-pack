// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _QUOTE_H_
#define _QUOTE_H_

#include <mbedtls/x509_crt.h>
#include <sgx_quote_3.h>
#include <stdbool.h>

bool is_quote_header_well_formed(const sgx_quote3_t *quote);
int verify_quote(const sgx_quote3_t *quote, mbedtls_x509_crt *root_crt);

#endif
