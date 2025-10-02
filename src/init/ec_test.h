// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "ec.h"
#include "test.h"
#include "utils.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>

static void test_read_write_raw_pk_roundtrip() {
	mbedtls_ecp_group grp;
	mbedtls_ecp_group_init(&grp);
	must(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) == 0, "Failed to load group");

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	must(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) == 0,
	     "Failed to seed DRBG");

	mbedtls_mpi sk;
	mbedtls_ecp_point written_pk;
	mbedtls_mpi_init(&sk);
	mbedtls_ecp_point_init(&written_pk);

	must(mbedtls_ecp_gen_keypair(&grp, &sk, &written_pk, mbedtls_ctr_drbg_random, &ctr_drbg) ==
	         0,
	     "Failed to generate keypair");

	uint8_t raw_pk[64];
	must(write_raw_pk(&grp, &written_pk, raw_pk) == 0, "write_raw_pk must succeed");

	mbedtls_ecp_point read_pk;
	mbedtls_ecp_point_init(&read_pk);
	must(read_raw_pk(&grp, raw_pk, &read_pk) == 0, "read_raw_pk must succeed");

	must(mbedtls_ecp_point_cmp(&written_pk, &read_pk) == 0,
	     "Roundtrip write_raw_pk/read_raw_pk must preserve the point");

	mbedtls_ecp_point_free(&read_pk);
	mbedtls_ecp_point_free(&written_pk);
	mbedtls_mpi_free(&sk);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

static void test_read_raw_sk() {
	uint8_t raw_sk[32];
	for (size_t i = 0; i < sizeof_array(raw_sk); i++) {
		raw_sk[i] = (uint8_t)(0xAA ^ i);
	}

	mbedtls_mpi sk;
	mbedtls_mpi_init(&sk);

	must(read_raw_sk(raw_sk, &sk) == 0, "read_raw_sk must succeed");
	must(mbedtls_mpi_cmp_int(&sk, 0) > 0, "sk must be nonzero");

	mbedtls_mpi_free(&sk);
}

static void test_read_raw_sig() {
	uint8_t raw_sig[64];
	for (size_t i = 0; i < sizeof_array(raw_sig); i++) {
		raw_sig[i] = (uint8_t)(0xAA ^ i);
	}

	mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	must(read_raw_sig(raw_sig, &r, &s) == 0, "read_raw_sig must succeed");
	must(mbedtls_mpi_cmp_int(&r, 0) > 0, "r must be nonzero");
	must(mbedtls_mpi_cmp_int(&s, 0) > 0, "s must be nonzero");

	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
}

static void test_ec() {
	test_read_write_raw_pk_roundtrip();
	test_read_raw_sig();
	test_read_raw_sk();
}