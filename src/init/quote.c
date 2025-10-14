// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "der.h"
#include "ec.h"
#include "utils.h"
#include <inttypes.h>
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

bool is_quote_header_well_formed(const sgx_quote3_t *quote) {
	trace("Checking if quote is well-formed...\n");
	bool is_well_formed = true;

	if (quote->header.version != 3) {
		trace("Unsupported quote version %d\n", quote->header.version);
		is_well_formed = false;
	}

	if (quote->header.att_key_type != SGX_QL_ALG_ECDSA_P256) {
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
		trace("Quote signature data length %" PRIu32 " is outside of [%zu, %d] range\n",
		      quote->signature_data_len, min_signature_data_len,
		      MAX_QUOTE_SIGNATURE_DATA_LENGTH);
		is_well_formed = false;
	}

	trace("Quote header is well-formed: %d\n", is_well_formed);
	return is_well_formed;
}

#pragma pack(push, 1)

struct ql_ecdsa_sig_data_header {
	uint8_t sig[64];
	uint8_t attest_pub_key[64];
	sgx_report_body_t qe_report;
	uint8_t qe_report_sig[64];
};

struct ql_auth_data_header {
	uint16_t size;
};

struct ql_certification_data_header {
	uint16_t cert_key_type;
	uint32_t size;
};

#pragma pack(pop)

struct parsed_quote {
	const uint8_t *quote;
	struct ql_ecdsa_sig_data_header sig_data_header;
	struct ql_auth_data_header auth_data_header;
	const uint8_t *auth_data;
	struct ql_certification_data_header crt_data_header;
	const uint8_t *crt_data;
};

static int parse_quote(const sgx_quote3_t *quote, struct parsed_quote *out_quote) {
	out_quote->quote = (const uint8_t *)quote;

	const uint8_t *p = (const uint8_t *)quote->signature_data;
	uint64_t remaining = quote->signature_data_len;

	if (remaining < sizeof out_quote->sig_data_header) {
		trace("Not enough bytes for sig_data_header\n");
		return -1;
	}
	memcpy(&out_quote->sig_data_header, p, sizeof out_quote->sig_data_header);
	p += sizeof out_quote->sig_data_header;
	remaining -= sizeof out_quote->sig_data_header;

	if (remaining < sizeof out_quote->auth_data_header) {
		trace("Not enough bytes for auth_data_header\n");
		return -1;
	}
	memcpy(&out_quote->auth_data_header, p, sizeof out_quote->auth_data_header);
	p += sizeof out_quote->auth_data_header;
	remaining -= sizeof out_quote->auth_data_header;

	if (remaining < out_quote->auth_data_header.size) {
		trace("Not enough bytes for auth_data\n");
		return -1;
	}
	out_quote->auth_data = p;
	p += out_quote->auth_data_header.size;
	remaining -= out_quote->auth_data_header.size;

	if (remaining < sizeof out_quote->crt_data_header) {
		trace("Not enough bytes for crt_data_header\n");
		return -1;
	}
	memcpy(&out_quote->crt_data_header, p, sizeof out_quote->crt_data_header);
	p += sizeof out_quote->crt_data_header;
	remaining -= sizeof out_quote->crt_data_header;

	if (remaining != out_quote->crt_data_header.size) {
		trace("Not enough or more than needed bytes for crt_data\n");
		return -1;
	}
	out_quote->crt_data = p;
	return 0;
}

static int verify_sig(mbedtls_pk_context *pk, const uint8_t sig[static 64], const uint8_t *msg,
                      size_t msg_len) {
	trace("Verifying a signature...\n");
	uint8_t sig_der[MBEDTLS_ECDSA_MAX_LEN] = {0};
	size_t sig_der_len = MBEDTLS_ECDSA_MAX_LEN;
	uint8_t hash[32] = {0};
	bool signature_is_valid = true;

	int err = rs_to_der(sig, sig_der, sig_der_len, &sig_der_len);
	if (err) {
		trace("rs_to_der failed: %d\n", err);
		signature_is_valid = false;
	}

	err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const uint8_t *)msg,
	                 msg_len, hash);
	if (err) {
		trace("mbedtls_md failed: %d\n", err);
		signature_is_valid = false;
	}

	err = mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, hash, sizeof hash, sig_der, sig_der_len);
	if (err) {
		trace("Invalid signature: %d\n", err);
		signature_is_valid = false;
	}

	trace("The signature is valid: %d\n", signature_is_valid);

	return signature_is_valid ? 0 : -1;
}

static int verify_qe_report_sig(const struct parsed_quote *quote, mbedtls_x509_crt *root_crt) {
	trace("Verifying QE report signature...\n");
	mbedtls_x509_crt pck_crt;
	uint32_t flags = 0;
	bool signature_is_valid = true;

	mbedtls_x509_crt_init(&pck_crt);

	if (quote->crt_data_header.cert_key_type != PCK_CERT_CHAIN) {
		trace("Unsupported ceritificate key type failed: %d\n",
		      quote->crt_data_header.cert_key_type);
		signature_is_valid = false;
	}

	int err = mbedtls_x509_crt_parse(&pck_crt, quote->crt_data, quote->crt_data_header.size);
	if (err) {
		trace("mbedtls_x509_crt_parse failed: %d\n", err);
		signature_is_valid = false;
	}

#ifdef ENABLE_TRACE
	char crt_info[1024] = {0};
	for (mbedtls_x509_crt *pck_crt_p = &pck_crt; pck_crt_p != NULL;
	     pck_crt_p = pck_crt_p->next) {
		if (mbedtls_x509_crt_info(crt_info, sizeof crt_info, "", pck_crt_p) > 0) {
			trace("%s", crt_info);
		} else {
			trace("Could not get certificate info\n");
		}
	}
#endif

	err = mbedtls_x509_crt_verify(&pck_crt, root_crt, NULL, NULL, &flags, NULL, NULL);
	if (err) {
		trace("Could not verify PCK certificate: %d\n", err);
		signature_is_valid = false;
	}

	if (flags) {
		trace("Invalid PCK certificate: %x\n", flags);
		signature_is_valid = false;
#ifdef ENABLE_TRACE
		char crt_verify_info[1024] = {0};
		if (mbedtls_x509_crt_verify_info(crt_verify_info, sizeof crt_verify_info, "",
		                                 flags) > 0) {
			trace("%s", crt_verify_info);
		}
#endif
	}

	err = verify_sig(&pck_crt.pk, quote->sig_data_header.qe_report_sig,
	                 (const uint8_t *)&quote->sig_data_header.qe_report,
	                 sizeof(sgx_report_body_t));
	if (err) {
		trace("Invalid QE report signature: %d\n", err);
		signature_is_valid = false;
	}

	trace("QE report signature is valid: %d\n", signature_is_valid);

	mbedtls_x509_crt_free(&pck_crt);
	return signature_is_valid ? 0 : -1;
}

static int verify_attest_key_hash(const struct parsed_quote *quote) {
	trace("Verifying attestation key hash...\n");
	uint8_t expected_report_data[SGX_REPORT_DATA_SIZE] = {0};
	uint8_t *hash_preimage = NULL;

	hash_preimage =
	    malloc(sizeof quote->sig_data_header.attest_pub_key + quote->auth_data_header.size);
	if (!hash_preimage) {
		trace("could not malloc for hash_preimage\n");
		return -1;
	}

	memcpy(hash_preimage, quote->sig_data_header.attest_pub_key,
	       sizeof quote->sig_data_header.attest_pub_key);
	memcpy(hash_preimage + sizeof quote->sig_data_header.attest_pub_key, quote->auth_data,
	       quote->auth_data_header.size);

	bool hash_is_valid = true;

	int err =
	    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), hash_preimage,
	               sizeof quote->sig_data_header.attest_pub_key + quote->auth_data_header.size,
	               expected_report_data);
	if (err) {
		trace("mbedtls_md failed: %d\n", err);
		hash_is_valid = false;
	}

	if (mbedtls_ct_memcmp(&quote->sig_data_header.qe_report.report_data, expected_report_data,
	                      SGX_REPORT_DATA_SIZE) != 0) {
		trace("Report data does not match\n");
		hash_is_valid = false;
	}

	trace("Attestation key hash is valid: %d\n", hash_is_valid);

	free(hash_preimage);

	return hash_is_valid ? 0 : -1;
}

static int verify_quote_sig(const struct parsed_quote *quote) {
	trace("Verifying quote signature...\n");

	uint8_t pk_der[128] = {0};
	size_t pk_der_len = sizeof pk_der;
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	bool signature_is_valid = true;

	int err =
	    pk_to_der(quote->sig_data_header.attest_pub_key, pk_der, sizeof pk_der, &pk_der_len);
	if (err) {
		trace("pk_to_der failed: %d\n", err);
		signature_is_valid = false;
	}

	err = mbedtls_pk_parse_public_key(&pk, pk_der, pk_der_len);
	if (err) {
		trace("mbedtls_pk_parse_public_key failed: %d\n", err);
		signature_is_valid = false;
	}

	err = verify_sig(&pk, quote->sig_data_header.sig, quote->quote,
	                 sizeof(sgx_quote_header_t) + sizeof(sgx_report_body_t));
	if (err) {
		trace("Invalid quote signature: %d\n", err);
		signature_is_valid = false;
	}

	trace("Quote signature is valid: %d\n", signature_is_valid);

	mbedtls_pk_free(&pk);

	return signature_is_valid ? 0 : -1;
}

int verify_quote(const sgx_quote3_t *quote, mbedtls_x509_crt *root_crt) {
	trace("Verifying quote...\n");

	struct parsed_quote parsed = {0};
	int err = parse_quote(quote, &parsed);
	if (err) {
		trace("Could not parse the quote: %d\n", err);
		return err;
	}

	bool quote_is_valid = true;
	err = verify_qe_report_sig(&parsed, root_crt);
	if (err) {
		trace("Invalid QE report: %d\n", err);
		quote_is_valid = false;
	}

	err = verify_attest_key_hash(&parsed);
	if (err) {
		trace("verify_attest_key_hash failed: %d\n", err);
		quote_is_valid = false;
	}

	err = verify_quote_sig(&parsed);
	if (err) {
		trace("verify_quote_sig failed: %d\n", err);
		quote_is_valid = false;
	}

	trace("Quote is valid: %d\n", quote_is_valid);

	return quote_is_valid ? 0 : -1;
}