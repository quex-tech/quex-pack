// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "ec.h"
#include "utils.h"
#include <mbedtls/ecp.h>
#include <string.h>

int read_raw_pk(const mbedtls_ecp_group *grp, const uint8_t raw[static 64],
                mbedtls_ecp_point *out_pk) {
	uint8_t uncompressed[65] = {0x04};
	memcpy(uncompressed + 1, raw, 64);
	return mbedtls_ecp_point_read_binary(grp, out_pk, uncompressed, sizeof uncompressed);
}

int write_raw_pk(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pk,
                 uint8_t out[static 64]) {
	uint8_t uncompressed[65] = {0x04};
	int err = mbedtls_ecp_point_write_binary(grp, pk, MBEDTLS_ECP_PF_UNCOMPRESSED, &(size_t){0},
	                                         uncompressed, sizeof uncompressed);
	if (err) {
		trace("mbedtls_ecp_point_write_binary failed: %d\n", err);
		return err;
	}
	memcpy(out, uncompressed + 1, 64);

#ifdef ENABLE_TRACE
	char pk_hex[129] = {0};
	write_hex(out, 64, pk_hex);
	trace("PK: %s\n", pk_hex);
#endif

	return 0;
}

int read_raw_sig(const uint8_t raw[static 64], mbedtls_mpi *out_r, mbedtls_mpi *out_s) {
	int err = mbedtls_mpi_read_binary(out_r, raw, 32);
	if (err) {
		trace("mbedtls_mpi_read_binary(r) failed: %d\n", err);
		return err;
	}

	err = mbedtls_mpi_read_binary(out_s, raw + 32, 32);
	if (err) {
		trace("mbedtls_mpi_read_binary(s) failed: %d\n", err);
		return err;
	}

	return 0;
}

int read_raw_sk(const uint8_t raw[static 32], mbedtls_mpi *out_sk) {
	int err = mbedtls_mpi_read_binary(out_sk, raw, 32);
	if (err) {
		trace("mbedtls_mpi_read_binary(sk) failed: %d\n", err);
		return err;
	}

	return 0;
}
