// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "ec.h"
#include "test.h"
#include "utils.h"
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <stddef.h>
#include <stdint.h>

void test_ec(void);

static void test_read_write_raw_pub_key_roundtrip(void) {
	mbedtls_ecp_group grp;
	mbedtls_ecp_group_init(&grp);
	must(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) == 0, "Failed to load group");

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	must(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) == 0,
	     "Failed to seed DRBG");

	mbedtls_mpi secret_key;
	mbedtls_ecp_point written_pk;
	mbedtls_mpi_init(&secret_key);
	mbedtls_ecp_point_init(&written_pk);

	must(mbedtls_ecp_gen_keypair(&grp, &secret_key, &written_pk, mbedtls_ctr_drbg_random,
	                             &ctr_drbg) == 0,
	     "Failed to generate keypair");

	uint8_t raw_pub_key[64];
	must(write_raw_pub_key(&grp, &written_pk, raw_pub_key) == 0,
	     "write_raw_pub_key must succeed");

	mbedtls_ecp_point read_pk;
	mbedtls_ecp_point_init(&read_pk);
	must(read_raw_pub_key(&grp, raw_pub_key, &read_pk) == 0, "read_raw_pub_key must succeed");

	must(mbedtls_ecp_point_cmp(&written_pk, &read_pk) == 0,
	     "Roundtrip write_raw_pub_key/read_raw_pub_key must preserve the point");

	mbedtls_ecp_point_free(&read_pk);
	mbedtls_ecp_point_free(&written_pk);
	mbedtls_mpi_free(&secret_key);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

static void test_read_raw_secret_key(void) {
	uint8_t raw_secret_key[32];
	for (size_t i = 0; i < sizeof_array(raw_secret_key); i++) {
		raw_secret_key[i] = (uint8_t)(0xaaU ^ i);
	}

	mbedtls_mpi secret_key;
	mbedtls_mpi_init(&secret_key);

	must(read_raw_secret_key(raw_secret_key, &secret_key) == 0,
	     "read_raw_secret_key must succeed");
	must(mbedtls_mpi_cmp_int(&secret_key, 0) > 0, "sk must be nonzero");

	mbedtls_mpi_free(&secret_key);
}

static void test_read_raw_sig(void) {
	uint8_t raw_sig[64];
	for (size_t i = 0; i < sizeof_array(raw_sig); i++) {
		raw_sig[i] = (uint8_t)(0xaaU ^ i);
	}

	mbedtls_mpi sig_r;
	mbedtls_mpi sig_s;
	mbedtls_mpi_init(&sig_r);
	mbedtls_mpi_init(&sig_s);

	must(read_raw_sig(raw_sig, &sig_r, &sig_s) == 0, "read_raw_sig must succeed");
	must(mbedtls_mpi_cmp_int(&sig_r, 0) > 0, "r must be nonzero");
	must(mbedtls_mpi_cmp_int(&sig_s, 0) > 0, "s must be nonzero");

	mbedtls_mpi_free(&sig_r);
	mbedtls_mpi_free(&sig_s);
}

void test_ec(void) {
	test_read_write_raw_pub_key_roundtrip();
	test_read_raw_sig();
	test_read_raw_secret_key();
}
