// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "der.h"
#include "ec.h"
#include "utils.h"
#include <mbedtls/asn1write.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <sgx_quote_3.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

bool is_quote_well_formed(sgx_quote3_t *quote) {
	trace("Checking if quote is well-formed...\n");

	if (quote->header.version != 3) {
		trace("Unsupported quote version %d\n", quote->header.version);
		return false;
	}

	if (quote->header.att_key_type != 2) {
		trace("Unsupported quote attestation key type %d\n", quote->header.att_key_type);
		return false;
	}

	if (quote->header.att_key_data_0 != 0) {
		trace("Unsupported quote attestation key data %x\n", quote->header.att_key_type);
		return false;
	}

	if (memcmp(quote->header.vendor_id,
	           (const uint8_t[]){0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A,
	                             0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07},
	           16) != 0) {
		trace("Unsupported quote vendor\n");
		return false;
	}

	if (quote->signature_data_len > 16384) {
		trace("Quote signature data length %d is too big\n", quote->signature_data_len);
		return false;
	}

	trace("Quote is well-formed\n");
	return true;
}

static int parse_pck_crt(mbedtls_x509_crt *pck_crt, sgx_ql_ecdsa_sig_data_t *signature_data) {
	trace("Parsing PCK certificate...\n");
	sgx_ql_auth_data_t *auth_data =
	    (sgx_ql_auth_data_t *)signature_data->auth_certification_data;
	sgx_ql_certification_data_t *crt_data =
	    (sgx_ql_certification_data_t *)(signature_data->auth_certification_data +
	                                    sizeof(sgx_ql_auth_data_t) + auth_data->size);
	trace("Certification data size: %d\n", crt_data->size);
	trace("Certification data last byte: %d\n",
	      crt_data->certification_data[crt_data->size - 1]);
	return mbedtls_x509_crt_parse(pck_crt, crt_data->certification_data, crt_data->size);
}

static int verify_sig(mbedtls_pk_context *pk, uint8_t sig[64], uint8_t *msg, size_t msg_len) {
	trace("Verifying a signature...\n");
	int ret = -1;
	uint8_t sig_der[MBEDTLS_ECDSA_MAX_LEN];
	size_t sig_der_len = MBEDTLS_ECDSA_MAX_LEN;
	unsigned char hash[32];

	if ((ret = rs_to_der(sig, sig_der, sig_der_len, &sig_der_len)) != 0) {
		trace("rs_to_der failed: %d\n", ret);
		return ret;
	}

	if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
	                      (const unsigned char *)msg, msg_len, hash)) != 0) {
		trace("mbedtls_md failed: %d\n", ret);
		return ret;
	}

	if ((ret = mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig_der,
	                             sig_der_len)) != 0) {
		trace("Invalid signature: %d\n", ret);
		return ret;
	}

	trace("The signature is valid\n");
	return 0;
}

static int verify_qe_report_sig(sgx_ql_ecdsa_sig_data_t *signature_data,
                                mbedtls_x509_crt *root_crt) {
	trace("Verifying QE report signature...\n");
	int ret = -1;
	mbedtls_x509_crt pck_crt;
	uint32_t flags = 0;

	mbedtls_x509_crt_init(&pck_crt);

	if ((ret = parse_pck_crt(&pck_crt, signature_data)) != 0) {
		trace("parse_pck_crt failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_x509_crt_verify(&pck_crt, root_crt, NULL, NULL, &flags, NULL, NULL)) !=
	    0) {
		trace("Invalid PCK certificate: %d\n", ret);
		goto cleanup;
	}

	if ((ret = verify_sig(&pck_crt.pk, signature_data->qe_report_sig,
	                      (uint8_t *)&(signature_data->qe_report),
	                      sizeof(sgx_report_body_t))) != 0) {
		trace("Invalid QE report signature: %d\n", ret);
		goto cleanup;
	}

	trace("QE report signature is valid\n");
	ret = 0;
cleanup:
	mbedtls_x509_crt_free(&pck_crt);
	return ret;
}

static int verify_attest_key_hash(sgx_ql_ecdsa_sig_data_t *signature_data) {
	trace("Verifying attestation key hash...\n");
	int ret = -1;
	sgx_ql_auth_data_t *auth_data =
	    (sgx_ql_auth_data_t *)signature_data->auth_certification_data;
	uint8_t expected_report_data[SGX_REPORT_DATA_SIZE] = {0};
	uint8_t *hash_preimage = NULL;

	hash_preimage = malloc(sizeof(signature_data->attest_pub_key) + auth_data->size);
	if (!hash_preimage) {
		trace("could not malloc for hash_preimage\n");
		goto cleanup;
	}

	memcpy(hash_preimage, signature_data->attest_pub_key,
	       sizeof(signature_data->attest_pub_key));
	memcpy(hash_preimage + sizeof(signature_data->attest_pub_key), auth_data->auth_data,
	       auth_data->size);

	if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
	                      (const unsigned char *)hash_preimage,
	                      sizeof(signature_data->attest_pub_key) + auth_data->size,
	                      expected_report_data)) != 0) {
		trace("mbedtls_md failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = memcmp(&(signature_data->qe_report.report_data), expected_report_data,
	                  SGX_REPORT_DATA_SIZE)) != 0) {
		trace("Report data does not match\n");
		goto cleanup;
	}

	trace("Attestation key hash is valid\n");
	ret = 0;
cleanup:
	if (hash_preimage) {
		free(hash_preimage);
	}
	return ret;
}

static int verify_quote_sig(sgx_quote3_t *quote) {
	trace("Verifying quote signature...\n");
	int ret = -1;

	uint8_t pk_der[128] = {0};
	size_t pk_der_len = sizeof(pk_der);
	mbedtls_pk_context pk;
	sgx_ql_ecdsa_sig_data_t *signature_data =
	    (sgx_ql_ecdsa_sig_data_t *)&(quote->signature_data);

	mbedtls_pk_init(&pk);

	if ((ret =
	         pk_to_der(signature_data->attest_pub_key, pk_der, sizeof(pk_der), &pk_der_len))) {
		trace("pk_to_der failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_pk_parse_public_key(&pk, pk_der, pk_der_len))) {
		trace("mbedtls_pk_parse_public_key failed: %d\n", ret);
		goto cleanup;
	}

	if ((ret = verify_sig(&pk, signature_data->sig, (uint8_t *)quote,
	                      sizeof(sgx_quote_header_t) + sizeof(sgx_report_body_t))) != 0) {
		trace("Invalid quote signature: %d\n", ret);
		goto cleanup;
	}

	trace("Quote signature is valid\n");
	ret = 0;
cleanup:
	mbedtls_pk_free(&pk);
	return ret;
}

int verify_quote(sgx_quote3_t *quote, mbedtls_x509_crt *root_crt) {
	trace("Verifying quote...\n");
	int ret = -1;
	sgx_ql_ecdsa_sig_data_t *signature_data =
	    (sgx_ql_ecdsa_sig_data_t *)&(quote->signature_data);

	if ((ret = verify_qe_report_sig(signature_data, root_crt)) != 0) {
		trace("Invalid QE report: %d\n", ret);
		return ret;
	}

	if ((ret = verify_attest_key_hash(signature_data)) != 0) {
		trace("verify_attest_key_hash failed: %d\n", ret);
		return ret;
	}

	if ((ret = verify_quote_sig(quote)) != 0) {
		trace("verify_quote_sig failed: %d\n", ret);
		return ret;
	}

	trace("Quote is valid\n");
	return 0;
}