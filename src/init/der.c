// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "der.h"
#include "ec.h"
#include "utils.h"
#include <mbedtls/asn1write.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <stdint.h>
#include <string.h>

// based on ecdsa_signature_to_asn1 from vendor/src/mbedtls-3.6.3/library/ecdsa.c
// Copyright The Mbed TLS Contributors
// SPDX-License-Identifier: Apache-2.0
static int rs_to_der_inner(const mbedtls_mpi *r, const mbedtls_mpi *s, uint8_t *out_der,
                           size_t max_der_len, size_t *out_der_len) {
	uint8_t buf[MBEDTLS_ECDSA_MAX_LEN] = {0};
	uint8_t *p = buf + sizeof buf;
	size_t len = 0;

	int ret = mbedtls_asn1_write_mpi(&p, buf, s);
	if (ret < 0) {
		return ret;
	}
	len += (size_t)ret;

	ret = mbedtls_asn1_write_mpi(&p, buf, r);
	if (ret < 0) {
		return ret;
	}
	len += (size_t)ret;

	ret = mbedtls_asn1_write_len(&p, buf, len);
	if (ret < 0) {
		return ret;
	}
	len += (size_t)ret;

	ret = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (ret < 0) {
		return ret;
	}
	len += (size_t)ret;

	if (len > max_der_len) {
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}

	memcpy(out_der, p, len);
	*out_der_len = len;

	return 0;
}

int rs_to_der(const uint8_t rs[64], uint8_t *out_der, size_t max_der_len, size_t *out_der_len) {
	int ret = 0;
	mbedtls_mpi r;
	mbedtls_mpi s;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	int err = read_raw_sig(rs, &r, &s);
	if (err) {
		trace("read_raw_sig failed: %d\n", err);
		ret = -1;
	}

	err = rs_to_der_inner(&r, &s, out_der, max_der_len, out_der_len);
	if (err) {
		trace("rs_to_der_inner failed: %d\n", err);
		ret = -1;
	}

	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);

	return ret;
}

int pk_to_der(const uint8_t pk[64], uint8_t *out_der, size_t max_der_len, size_t *out_der_len) {
	uint8_t *p = out_der + max_der_len;
	size_t len = 0;
	size_t len_alg = 0;
	uint8_t point[65] = {[0] = 0x04};
	memcpy(point + 1, pk, 64);

	int ret = mbedtls_asn1_write_bitstring(&p, out_der, point, 65 * 8);
	if (ret < 0) {
		return ret;
	}
	len += (size_t)ret;

	ret = mbedtls_asn1_write_oid(&p, out_der, MBEDTLS_OID_EC_GRP_SECP256R1,
	                             MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP256R1));
	if (ret < 0) {
		return ret;
	}
	len_alg += (size_t)ret;

	ret = mbedtls_asn1_write_oid(&p, out_der, MBEDTLS_OID_EC_ALG_UNRESTRICTED,
	                             MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_ALG_UNRESTRICTED));
	if (ret < 0) {
		return ret;
	}
	len_alg += (size_t)ret;

	ret = mbedtls_asn1_write_len(&p, out_der, len_alg);
	if (ret < 0) {
		return ret;
	}
	len_alg += (size_t)ret;

	ret = mbedtls_asn1_write_tag(&p, out_der, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (ret < 0) {
		return ret;
	}
	len_alg += (size_t)ret;

	len += len_alg;

	ret = mbedtls_asn1_write_len(&p, out_der, len);
	if (ret < 0) {
		return ret;
	}
	len += (size_t)ret;

	ret = mbedtls_asn1_write_tag(&p, out_der, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (ret < 0) {
		return ret;
	}
	len += (size_t)ret;

	if (len > max_der_len) {
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}

	memmove(out_der, p, len);
	*out_der_len = len;

	return 0;
}
