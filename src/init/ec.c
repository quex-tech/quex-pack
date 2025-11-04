// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "ec.h"
#include "utils.h"
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <stdint.h>
#include <string.h>

int read_raw_pub_key(const mbedtls_ecp_group *grp, const uint8_t raw[64],
                     mbedtls_ecp_point *out_pk) {
	uint8_t uncompressed[65] = {[0] = 0x04};
	memcpy(uncompressed + 1, raw, 64);
	return mbedtls_ecp_point_read_binary(grp, out_pk, uncompressed, sizeof uncompressed);
}

int write_raw_pub_key(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pub_key,
                      uint8_t out[64]) {
	uint8_t uncompressed[65] = {[0] = 0x04};
	size_t olen = 0;
	int err = mbedtls_ecp_point_write_binary(grp, pub_key, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
	                                         uncompressed, sizeof uncompressed);
	if (err) {
		trace("mbedtls_ecp_point_write_binary failed: %d\n", err);
		return err;
	}
	memcpy(out, uncompressed + 1, 64);

#ifdef ENABLE_TRACE
	char pub_key_hex[129] = {0};
	write_hex(out, 64, pub_key_hex, sizeof pub_key_hex);
	trace("PK: %s\n", pub_key_hex);
#endif

	return 0;
}

int read_raw_sig(const uint8_t raw[64], mbedtls_mpi *out_r, mbedtls_mpi *out_s) {
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

int read_raw_secret_key(const uint8_t raw[32], mbedtls_mpi *out_secret_key) {
	int err = mbedtls_mpi_read_binary(out_secret_key, raw, 32);
	if (err) {
		trace("mbedtls_mpi_read_binary(sk) failed: %d\n", err);
		return err;
	}

	return 0;
}
