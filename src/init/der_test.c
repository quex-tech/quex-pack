// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "der.h"
#include "ec.h"
#include "test.h"
#include "utils.h"
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <stddef.h>
#include <stdint.h>

void test_der(void);

static int write_raw_sig(const mbedtls_mpi *sig_r, const mbedtls_mpi *sig_s, uint8_t out[64]) {
	int err = mbedtls_mpi_write_binary(sig_r, out, 32);
	if (err) {
		trace("mbedtls_mpi_write_binary(sig_r) failed: %d\n", err);
		return err;
	}

	err = mbedtls_mpi_write_binary(sig_s, out + 32, 32);
	if (err) {
		trace("mbedtls_mpi_write_binary(sig_s) failed: %d\n", err);
		return err;
	}

	return 0;
}

static void test_rs_to_der(void) {
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
	mbedtls_ecp_point pub_key;
	mbedtls_mpi_init(&secret_key);
	mbedtls_ecp_point_init(&pub_key);
	must(mbedtls_ecp_gen_keypair(&grp, &secret_key, &pub_key, mbedtls_ctr_drbg_random,
	                             &ctr_drbg) == 0,
	     "mbedtls_ecp_gen_keypair failed");

	const uint8_t msg[] = "hello world";
	uint8_t hash[32];
	mbedtls_md_context_t md_ctx;
	mbedtls_md_init(&md_ctx);
	must(mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0) == 0,
	     "mbedtls_md_setup failed");
	must(mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg, sizeof msg - 1, hash) ==
	         0,
	     "mbedtls_md failed");
	mbedtls_md_free(&md_ctx);

	mbedtls_mpi sig_r;
	mbedtls_mpi sig_s;
	mbedtls_mpi_init(&sig_r);
	mbedtls_mpi_init(&sig_s);
	must(mbedtls_ecdsa_sign(&grp, &sig_r, &sig_s, &secret_key, hash, sizeof hash,
	                        mbedtls_ctr_drbg_random, &ctr_drbg) == 0,
	     "mbedtls_ecdsa_sign failed");

	uint8_t raw_sig_rs[64];
	must(write_raw_sig(&sig_r, &sig_s, raw_sig_rs) == 0, "write_raw_sig must succeed");

	uint8_t sig_der[128];
	ptrdiff_t sig_der_len = 0;
	must(rs_to_der(raw_sig_rs, sig_der, sizeof sig_der, &sig_der_len) == 0,
	     "rs_to_der must succeed");
	must(sig_der_len > 0, "sig_der_len must be > 0");

	must(mbedtls_ecdsa_verify(&grp, hash, sizeof hash, &pub_key, &sig_r, &sig_s) == 0,
	     "mbedtls_ecdsa_verify must succeed");

	mbedtls_mpi_free(&sig_s);
	mbedtls_mpi_free(&sig_r);
	mbedtls_ecp_point_free(&pub_key);
	mbedtls_mpi_free(&secret_key);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

static void test_pub_key_to_der(void) {
	mbedtls_ecp_group grp;
	mbedtls_ecp_group_init(&grp);
	must(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0, "Failed to load group");

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	must(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) == 0,
	     "Failed to seed DRBG");

	mbedtls_mpi secret_key;
	mbedtls_ecp_point pub_key;
	mbedtls_mpi_init(&secret_key);
	mbedtls_ecp_point_init(&pub_key);
	must(mbedtls_ecp_gen_keypair(&grp, &secret_key, &pub_key, mbedtls_ctr_drbg_random,
	                             &ctr_drbg) == 0,
	     "Failed to gen keypair");

	uint8_t pub_key_raw[64] = {0};
	must(write_raw_pub_key(&grp, &pub_key, pub_key_raw) == 0, "write_raw_pub_key must succeed");

	uint8_t pub_key_der[128] = {0};
	ptrdiff_t pub_key_der_len = 0;
	must(pub_key_to_der(pub_key_raw, pub_key_der, sizeof pub_key_der, &pub_key_der_len) == 0,
	     "pub_key_to_der must succeed");
	must(pub_key_der_len > 0, "pub_key_der_len must be > 0");

	mbedtls_pk_context pub_key_ctx;
	mbedtls_pk_init(&pub_key_ctx);
	must(mbedtls_pk_parse_public_key(&pub_key_ctx, pub_key_der, (size_t)pub_key_der_len) == 0,
	     "mbedtls_pk_parse_public_key must succeed");

	mbedtls_pk_free(&pub_key_ctx);
	mbedtls_ecp_point_free(&pub_key);
	mbedtls_mpi_free(&secret_key);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

void test_der(void) {
	test_rs_to_der();
	test_pub_key_to_der();
}
