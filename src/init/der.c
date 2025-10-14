// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "ec.h"
#include "utils.h"
#include <mbedtls/asn1write.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <stdint.h>
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

// copied from vendor/src/mbedtls-3.6.3/library/ecdsa.c
// Copyright The Mbed TLS Contributors
// SPDX-License-Identifier: Apache-2.0
static int ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s, uint8_t *sig,
                                   size_t sig_len, size_t *out_sig_len) {
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint8_t buf[MBEDTLS_ECDSA_MAX_LEN] = {0};
	uint8_t *p = buf + sizeof buf;
	size_t len = 0;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
	MBEDTLS_ASN1_CHK_ADD(
	    len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	if (len > sig_len) {
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}

	memcpy(sig, p, len);
	*out_sig_len = len;

	return 0;
}

int rs_to_der(const uint8_t rs[static 64], uint8_t *out_der, size_t max_der_len,
              size_t *out_der_len) {
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

	err = ecdsa_signature_to_asn1(&r, &s, out_der, max_der_len, out_der_len);
	if (err) {
		trace("ecdsa_signature_to_asn1 failed: %d\n", err);
		ret = -1;
	}

	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);

	return ret;
}

int pk_to_der(const uint8_t pk[static 64], uint8_t *out_der, size_t max_der_len,
              size_t *out_der_len) {
	int ret = -1;
	uint8_t *p = out_der + max_der_len;
	size_t len = 0;
	size_t len_alg = 0;
	uint8_t point[65] = {0x04};
	memcpy(point + 1, pk, 64);

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&p, out_der, point, 65 * 8));

	MBEDTLS_ASN1_CHK_ADD(
	    len_alg, mbedtls_asn1_write_oid(&p, out_der, MBEDTLS_OID_EC_GRP_SECP256R1,
	                                    MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP256R1)));
	MBEDTLS_ASN1_CHK_ADD(
	    len_alg, mbedtls_asn1_write_oid(&p, out_der, MBEDTLS_OID_EC_ALG_UNRESTRICTED,
	                                    MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_ALG_UNRESTRICTED)));
	MBEDTLS_ASN1_CHK_ADD(len_alg, mbedtls_asn1_write_len(&p, out_der, len_alg));
	MBEDTLS_ASN1_CHK_ADD(
	    len_alg,
	    mbedtls_asn1_write_tag(&p, out_der, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	len += len_alg;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, out_der, len));
	MBEDTLS_ASN1_CHK_ADD(
	    len,
	    mbedtls_asn1_write_tag(&p, out_der, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	*out_der_len = len;
	memmove(out_der, p, len);

	return 0;
}

#pragma GCC diagnostic pop
