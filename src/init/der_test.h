// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "der.h"
#include "ec.h"
#include "test.h"
#include "utils.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <string.h>

static int write_raw_sig(const mbedtls_mpi *r, const mbedtls_mpi *s, uint8_t out[64]) {
	int err;

	err = mbedtls_mpi_write_binary(r, out, 32);
	if (err) {
		trace("mbedtls_mpi_write_binary(r) failed: %d\n", err);
		return err;
	}

	err = mbedtls_mpi_write_binary(s, out + 32, 32);
	if (err) {
		trace("mbedtls_mpi_write_binary(s) failed: %d\n", err);
		return err;
	}

	return 0;
}

static void test_rs_to_der() {
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
	mbedtls_ecp_point pk;
	mbedtls_mpi_init(&sk);
	mbedtls_ecp_point_init(&pk);
	must(mbedtls_ecp_gen_keypair(&grp, &sk, &pk, mbedtls_ctr_drbg_random, &ctr_drbg) == 0,
	     "mbedtls_ecp_gen_keypair failed");

	const uint8_t msg[] = "hello world";
	uint8_t hash[32];
	mbedtls_md_context_t md;
	mbedtls_md_init(&md);
	must(mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0) == 0,
	     "mbedtls_md_setup failed");
	must(mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg, sizeof(msg) - 1, hash) ==
	         0,
	     "mbedtls_md failed");
	mbedtls_md_free(&md);

	mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	must(mbedtls_ecdsa_sign(&grp, &r, &s, &sk, hash, sizeof(hash), mbedtls_ctr_drbg_random,
	                        &ctr_drbg) == 0,
	     "mbedtls_ecdsa_sign failed");

	uint8_t raw_sig[64];
	must(write_raw_sig(&r, &s, raw_sig) == 0, "write_raw_sig must succeed");

	uint8_t sig_der[128];
	size_t sig_der_len = 0;
	must(rs_to_der(raw_sig, sig_der, sizeof(sig_der), &sig_der_len) == 0,
	     "rs_to_der must succeed");
	must(sig_der_len > 0, "sig_der_len must be > 0");

	must(mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &pk, &r, &s) == 0,
	     "mbedtls_ecdsa_verify must succeed");

	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_ecp_point_free(&pk);
	mbedtls_mpi_free(&sk);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

static void test_pk_to_der() {
	mbedtls_ecp_group grp;
	mbedtls_ecp_group_init(&grp);
	must(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0, "Failed to load group");

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	must(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) == 0,
	     "Failed to seed DRBG");

	mbedtls_mpi sk;
	mbedtls_ecp_point pk;
	mbedtls_mpi_init(&sk);
	mbedtls_ecp_point_init(&pk);
	must(mbedtls_ecp_gen_keypair(&grp, &sk, &pk, mbedtls_ctr_drbg_random, &ctr_drbg) == 0,
	     "Failed to gen keypair");

	uint8_t raw_pk[64] = {0};
	must(write_raw_pk(&grp, &pk, raw_pk) == 0, "write_raw_pk must succeed");

	uint8_t pk_der[128] = {0};
	size_t pk_der_len = 0;
	must(pk_to_der(raw_pk, pk_der, sizeof pk_der, &pk_der_len) == 0, "pk_to_der must succeed");
	must(pk_der_len > 0, "pk_der_len must be > 0");

	mbedtls_pk_context pk_ctx;
	mbedtls_pk_init(&pk_ctx);
	must(mbedtls_pk_parse_public_key(&pk_ctx, pk_der, pk_der_len) == 0,
	     "mbedtls_pk_parse_public_key must succeed");

	mbedtls_pk_free(&pk_ctx);
	mbedtls_ecp_point_free(&pk);
	mbedtls_mpi_free(&sk);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

static void test_der() {
	test_rs_to_der();
	test_pk_to_der();
}
