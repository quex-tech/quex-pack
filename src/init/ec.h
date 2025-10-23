// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef EC_H
#define EC_H

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <stdint.h>

int read_raw_pk(const mbedtls_ecp_group *grp, const uint8_t raw[64], mbedtls_ecp_point *out_pk);
int write_raw_pk(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pk, uint8_t out[64]);
int read_raw_sig(const uint8_t raw[64], mbedtls_mpi *out_r, mbedtls_mpi *out_s);
int read_raw_sk(const uint8_t raw[32], mbedtls_mpi *out_sk);

#endif
