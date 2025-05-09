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

	return true;
}

static int parse_pck_crt(mbedtls_x509_crt *pck_crt, sgx_ql_ecdsa_sig_data_t *signature_data) {
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

static int verify_qe_report_sig(sgx_ql_ecdsa_sig_data_t *signature_data,
                                mbedtls_x509_crt *root_crt) {
	int ret = -1;
	mbedtls_x509_crt pck_crt;
	uint8_t sig_der[MBEDTLS_ECDSA_MAX_LEN];
	size_t sig_der_len = MBEDTLS_ECDSA_MAX_LEN;
	unsigned char hash[32];
	uint32_t flags = 0;

	mbedtls_x509_crt_init(&pck_crt);

	if ((ret = parse_pck_crt(&pck_crt, signature_data)) != 0) {
		trace("parse_pck_crt failed\n");
		goto cleanup;
	}

	if ((ret = mbedtls_x509_crt_verify(&pck_crt, root_crt, NULL, NULL, &flags, NULL, NULL)) !=
	    0) {
		trace("Invalid PCK certificate\n");
		goto cleanup;
	}

	if ((ret = rs_to_der(signature_data->qe_report_sig, sig_der, sig_der_len, &sig_der_len)) !=
	    0) {
		trace("rs_to_der failed\n");
		return ret;
	}

	if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
	                      (const unsigned char *)&(signature_data->qe_report),
	                      sizeof(sgx_report_body_t), hash)) != 0) {
		trace("mbedtls_md failed\n");
		return ret;
	}

	if ((ret = mbedtls_pk_verify(&pck_crt.pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig_der,
	                             sig_der_len)) != 0) {
		trace("Invalid signature\n");
		return ret;
	}

	ret = 0;
cleanup:
	mbedtls_x509_crt_free(&pck_crt);
	return ret;
}

static int verify_attest_key_hash(sgx_ql_ecdsa_sig_data_t *signature_data) {
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
		trace("mbedtls_md failed\n");
		goto cleanup;
	}

	if ((ret = memcmp(&(signature_data->qe_report.report_data), expected_report_data,
	                  SGX_REPORT_DATA_SIZE)) != 0) {
		trace("Report data does not match\n");
		goto cleanup;
	}

	ret = 0;
cleanup:
	if (hash_preimage) {
		free(hash_preimage);
	}
	return ret;
}

static int verify_quote_sig(sgx_quote3_t *quote) {
	int ret = -1;
	sgx_ql_ecdsa_sig_data_t *signature_data =
	    (sgx_ql_ecdsa_sig_data_t *)&(quote->signature_data);
	unsigned char hash[32];
	mbedtls_ecp_group grp;
	mbedtls_ecp_point attest_pk;
	mbedtls_mpi r;
	mbedtls_mpi s;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&attest_pk);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if ((ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) != 0) {
		trace("mbedtls_ecp_group_load failed\n");
		goto cleanup;
	}

	if ((ret = read_raw_pk(&grp, signature_data->attest_pub_key, &attest_pk)) != 0) {
		trace("mbedtls_ecp_point_binary(attest_pk) failed\n");
		goto cleanup;
	}

	if ((ret = read_raw_sig(signature_data->sig, &r, &s)) != 0) {
		trace("read_raw_sig failed\n");
		goto cleanup;
	}

	if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
	                      (const unsigned char *)quote,
	                      sizeof(sgx_quote_header_t) + sizeof(sgx_report_body_t), hash)) != 0) {
		trace("mbedtls_md failed\n");
		return ret;
	}

	if ((ret = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &attest_pk, &r, &s)) != 0) {
		trace("Invalid signature\n");
		goto cleanup;
	}

	ret = 0;
cleanup:
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_ecp_point_free(&attest_pk);
	mbedtls_ecp_group_free(&grp);
	return ret;
}

int verify_quote(sgx_quote3_t *quote, mbedtls_x509_crt *root_crt) {
	int ret = -1;
	sgx_ql_ecdsa_sig_data_t *signature_data =
	    (sgx_ql_ecdsa_sig_data_t *)&(quote->signature_data);

	if ((ret = verify_qe_report_sig(signature_data, root_crt)) != 0) {
		trace("Invalid QE report\n");
		return ret;
	}

	if ((ret = verify_attest_key_hash(signature_data)) != 0) {
		trace("verify_attest_key_hash failed\n");
		return ret;
	}

	if ((ret = verify_quote_sig(quote)) != 0) {
		trace("verify_quote_sig failed\n");
		return ret;
	}

	return 0;
}