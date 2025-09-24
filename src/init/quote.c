// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "der.h"
#include "ec.h"
#include "utils.h"
#include <mbedtls/asn1write.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <sgx_quote_3.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define MAX_QUOTE_SIGNATURE_DATA_LENGTH 16384

bool is_quote_header_well_formed(sgx_quote3_t *quote) {
	trace("Checking if quote is well-formed...\n");
	bool is_well_formed = true;

	if (quote->header.version != 3) {
		trace("Unsupported quote version %d\n", quote->header.version);
		is_well_formed = false;
	}

	if (quote->header.att_key_type != 2) {
		trace("Unsupported quote attestation key type %d\n", quote->header.att_key_type);
		is_well_formed = false;
	}

	if (quote->header.att_key_data_0 != 0) {
		trace("Unsupported quote attestation key data %x\n", quote->header.att_key_data_0);
		is_well_formed = false;
	}

	if (mbedtls_ct_memcmp(quote->header.vendor_id,
	                      (const uint8_t[]){0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9,
	                                        0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07},
	                      16) != 0) {
		trace("Unsupported quote vendor\n");
		is_well_formed = false;
	}

	size_t min_signature_data_len = sizeof(sgx_ql_ecdsa_sig_data_t) +
	                                sizeof(sgx_ql_auth_data_t) +
	                                sizeof(sgx_ql_certification_data_t);
	if (min_signature_data_len > quote->signature_data_len ||
	    quote->signature_data_len > MAX_QUOTE_SIGNATURE_DATA_LENGTH) {
		trace("Quote signature data length %u is outside of [%zu, %u] range\n",
		      quote->signature_data_len, min_signature_data_len,
		      MAX_QUOTE_SIGNATURE_DATA_LENGTH);
		is_well_formed = false;
	}

	trace("Quote header is well-formed: %d\n", is_well_formed);
	return is_well_formed;
}

bool is_quote_well_formed(sgx_quote3_t *quote) {
	if (!is_quote_header_well_formed(quote)) {
		trace("Quote header is ill-formed\n");
		return false;
	}

	sgx_ql_ecdsa_sig_data_t *signature_data =
	    (sgx_ql_ecdsa_sig_data_t *)&(quote->signature_data);

	sgx_ql_auth_data_t *auth_data =
	    (sgx_ql_auth_data_t *)signature_data->auth_certification_data;

	size_t min_signature_data_len = sizeof(sgx_ql_ecdsa_sig_data_t) +
	                                sizeof(sgx_ql_auth_data_t) +
	                                sizeof(sgx_ql_certification_data_t);

	if (auth_data->size > quote->signature_data_len - min_signature_data_len) {
		trace("auth_data size is too big\n");
		return false;
	}

	sgx_ql_certification_data_t *crt_data =
	    (sgx_ql_certification_data_t *)(signature_data->auth_certification_data +
	                                    sizeof(sgx_ql_auth_data_t) + auth_data->size);

	if (crt_data->size !=
	    quote->signature_data_len - min_signature_data_len - auth_data->size) {
		trace("crt_data size is wrong\n");
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
	uint8_t sig_der[MBEDTLS_ECDSA_MAX_LEN] = {0};
	size_t sig_der_len = MBEDTLS_ECDSA_MAX_LEN;
	unsigned char hash[32] = {0};
	bool signature_is_valid = true;

	int err = rs_to_der(sig, sig_der, sig_der_len, &sig_der_len);
	if (err) {
		trace("rs_to_der failed: %d\n", err);
		signature_is_valid = false;
	}

	err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)msg,
	                 msg_len, hash);
	if (err) {
		trace("mbedtls_md failed: %d\n", err);
		signature_is_valid = false;
	}

	err = mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig_der, sig_der_len);
	if (err) {
		trace("Invalid signature: %d\n", err);
		signature_is_valid = false;
	}

	trace("The signature is valid: %d\n", signature_is_valid);

	return signature_is_valid ? 0 : -1;
}

static int verify_qe_report_sig(sgx_ql_ecdsa_sig_data_t *signature_data,
                                mbedtls_x509_crt *root_crt) {
	trace("Verifying QE report signature...\n");
	mbedtls_x509_crt pck_crt;
	uint32_t flags = 0;
	bool signature_is_valid = true;

	mbedtls_x509_crt_init(&pck_crt);

	int err = parse_pck_crt(&pck_crt, signature_data);
	if (err) {
		trace("parse_pck_crt failed: %d\n", err);
		signature_is_valid = false;
	}

	err = mbedtls_x509_crt_verify(&pck_crt, root_crt, NULL, NULL, &flags, NULL, NULL);
	if (err) {
		trace("Invalid PCK certificate: %d\n", err);
		signature_is_valid = false;
	}

	err = verify_sig(&pck_crt.pk, signature_data->qe_report_sig,
	                 (uint8_t *)&(signature_data->qe_report), sizeof(sgx_report_body_t));
	if (err) {
		trace("Invalid QE report signature: %d\n", err);
		signature_is_valid = false;
	}

	trace("QE report signature is valid: %d\n", signature_is_valid);

	mbedtls_x509_crt_free(&pck_crt);
	return signature_is_valid ? 0 : -1;
}

static int verify_attest_key_hash(sgx_ql_ecdsa_sig_data_t *signature_data) {
	trace("Verifying attestation key hash...\n");
	sgx_ql_auth_data_t *auth_data =
	    (sgx_ql_auth_data_t *)signature_data->auth_certification_data;
	uint8_t expected_report_data[SGX_REPORT_DATA_SIZE] = {0};
	uint8_t *hash_preimage = NULL;

	hash_preimage = malloc(sizeof(signature_data->attest_pub_key) + auth_data->size);
	if (!hash_preimage) {
		trace("could not malloc for hash_preimage\n");
		return -1;
	}

	memcpy(hash_preimage, signature_data->attest_pub_key,
	       sizeof(signature_data->attest_pub_key));
	memcpy(hash_preimage + sizeof(signature_data->attest_pub_key), auth_data->auth_data,
	       auth_data->size);

	bool hash_is_valid = true;

	int err = mbedtls_md(
	    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)hash_preimage,
	    sizeof(signature_data->attest_pub_key) + auth_data->size, expected_report_data);
	if (err) {
		trace("mbedtls_md failed: %d\n", err);
		hash_is_valid = false;
	}

	if (mbedtls_ct_memcmp(&(signature_data->qe_report.report_data), expected_report_data,
	                      SGX_REPORT_DATA_SIZE) != 0) {
		trace("Report data does not match\n");
		hash_is_valid = false;
	}

	trace("Attestation key hash is valid: %d\n", hash_is_valid);

	free(hash_preimage);

	return hash_is_valid ? 0 : -1;
}

static int verify_quote_sig(sgx_quote3_t *quote) {
	trace("Verifying quote signature...\n");

	uint8_t pk_der[128] = {0};
	size_t pk_der_len = sizeof(pk_der);
	mbedtls_pk_context pk;
	sgx_ql_ecdsa_sig_data_t *signature_data =
	    (sgx_ql_ecdsa_sig_data_t *)&(quote->signature_data);

	mbedtls_pk_init(&pk);

	bool signature_is_valid = true;

	int err = pk_to_der(signature_data->attest_pub_key, pk_der, sizeof(pk_der), &pk_der_len);
	if (err) {
		trace("pk_to_der failed: %d\n", err);
		signature_is_valid = false;
	}

	err = mbedtls_pk_parse_public_key(&pk, pk_der, pk_der_len);
	if (err) {
		trace("mbedtls_pk_parse_public_key failed: %d\n", err);
		signature_is_valid = false;
	}

	err = verify_sig(&pk, signature_data->sig, (uint8_t *)quote,
	                 sizeof(sgx_quote_header_t) + sizeof(sgx_report_body_t));
	if (err) {
		trace("Invalid quote signature: %d\n", err);
		signature_is_valid = false;
	}

	trace("Quote signature is valid: %d\n", signature_is_valid);

	mbedtls_pk_free(&pk);

	return signature_is_valid ? 0 : -1;
}

int verify_quote(sgx_quote3_t *quote, mbedtls_x509_crt *root_crt) {
	trace("Verifying quote...\n");
	sgx_ql_ecdsa_sig_data_t *signature_data =
	    (sgx_ql_ecdsa_sig_data_t *)&(quote->signature_data);

	bool quote_is_valid = true;
	int err = verify_qe_report_sig(signature_data, root_crt);
	if (err) {
		trace("Invalid QE report: %d\n", err);
		quote_is_valid = false;
	}

	err = verify_attest_key_hash(signature_data);
	if (err) {
		trace("verify_attest_key_hash failed: %d\n", err);
		quote_is_valid = false;
	}

	err = verify_quote_sig(quote);
	if (err) {
		trace("verify_quote_sig failed: %d\n", err);
		quote_is_valid = false;
	}

	trace("Quote is valid: %d\n", quote_is_valid);

	return quote_is_valid ? 0 : -1;
}