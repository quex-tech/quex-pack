// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "der.h"
#include "ec.h"
#include "utils.h"
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/oid.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// based on ecdsa_signature_to_asn1 from vendor/src/mbedtls-3.6.3/library/ecdsa.c
// Copyright The Mbed TLS Contributors
// SPDX-License-Identifier: Apache-2.0
static int rs_to_der_inner(const mbedtls_mpi *sig_r, const mbedtls_mpi *sig_s, uint8_t *out_der,
                           ptrdiff_t max_der_len, ptrdiff_t *out_der_len) {
	uint8_t buf[MBEDTLS_ECDSA_MAX_LEN] = {0};
	uint8_t *cur = buf + sizeof buf;
	ptrdiff_t len = 0;

	int ret = mbedtls_asn1_write_mpi(&cur, buf, sig_s);
	if (ret < 0) {
		return ret;
	}
	len += ret;

	ret = mbedtls_asn1_write_mpi(&cur, buf, sig_r);
	if (ret < 0) {
		return ret;
	}
	len += ret;

	ret = mbedtls_asn1_write_len(&cur, buf, (size_t)len);
	if (ret < 0) {
		return ret;
	}
	len += ret;

	ret = mbedtls_asn1_write_tag(
	    &cur, buf, (uint8_t)MBEDTLS_ASN1_CONSTRUCTED | (uint8_t)MBEDTLS_ASN1_SEQUENCE);
	if (ret < 0) {
		return ret;
	}
	len += ret;

	if (len > max_der_len) {
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}

	memcpy(out_der, cur, (size_t)len);
	*out_der_len = len;

	return 0;
}

int rs_to_der(const uint8_t sig_rs[64], uint8_t *out_der, ptrdiff_t max_der_len,
              ptrdiff_t *out_der_len) {
	if (max_der_len <= 0) {
		return -1;
	}

	int ret = 0;
	mbedtls_mpi sig_r;
	mbedtls_mpi sig_s;

	mbedtls_mpi_init(&sig_r);
	mbedtls_mpi_init(&sig_s);

	int err = read_raw_sig(sig_rs, &sig_r, &sig_s);
	if (err) {
		trace("read_raw_sig failed: %d\n", err);
		ret = -1;
	}

	err = rs_to_der_inner(&sig_r, &sig_s, out_der, max_der_len, out_der_len);
	if (err) {
		trace("rs_to_der_inner failed: %d\n", err);
		ret = -1;
	}

	mbedtls_mpi_free(&sig_s);
	mbedtls_mpi_free(&sig_r);

	return ret;
}

int pub_key_to_der(const uint8_t pub_key[64], uint8_t *out_der, ptrdiff_t max_der_len,
                   ptrdiff_t *out_der_len) {
	if (max_der_len <= 0) {
		return -1;
	}

	uint8_t *cur = out_der + max_der_len;
	ptrdiff_t len = 0;
	ptrdiff_t len_alg = 0;
	uint8_t point[65] = {[0] = 0x04};
	memcpy(point + 1, pub_key, 64);

	int ret = mbedtls_asn1_write_bitstring(&cur, out_der, point, 65UL * 8);
	if (ret < 0) {
		return ret;
	}
	len += ret;

	ret = mbedtls_asn1_write_oid(&cur, out_der, MBEDTLS_OID_EC_GRP_SECP256R1,
	                             MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP256R1));
	if (ret < 0) {
		return ret;
	}
	len_alg += ret;

	ret = mbedtls_asn1_write_oid(&cur, out_der, MBEDTLS_OID_EC_ALG_UNRESTRICTED,
	                             MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_ALG_UNRESTRICTED));
	if (ret < 0) {
		return ret;
	}
	len_alg += ret;

	ret = mbedtls_asn1_write_len(&cur, out_der, (size_t)len_alg);
	if (ret < 0) {
		return ret;
	}
	len_alg += ret;

	ret = mbedtls_asn1_write_tag(
	    &cur, out_der, (uint8_t)MBEDTLS_ASN1_CONSTRUCTED | (uint8_t)MBEDTLS_ASN1_SEQUENCE);
	if (ret < 0) {
		return ret;
	}
	len_alg += ret;

	len += len_alg;

	ret = mbedtls_asn1_write_len(&cur, out_der, (size_t)len);
	if (ret < 0) {
		return ret;
	}
	len += ret;

	ret = mbedtls_asn1_write_tag(
	    &cur, out_der, (uint8_t)MBEDTLS_ASN1_CONSTRUCTED | (uint8_t)MBEDTLS_ASN1_SEQUENCE);
	if (ret < 0) {
		return ret;
	}
	len += ret;

	if (len > max_der_len) {
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}

	memmove(out_der, cur, (size_t)len);
	*out_der_len = len;

	return 0;
}
