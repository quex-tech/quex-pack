#include "ec.h"
#include <mbedtls/asn1write.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <stdint.h>
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

// copied from vendor/src/mbedtls-3.6.3/library/ecdsa.c
static int ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s, unsigned char *sig,
                                   size_t sig_size, size_t *slen) {
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	unsigned char buf[MBEDTLS_ECDSA_MAX_LEN] = {0};
	unsigned char *p = buf + sizeof(buf);
	size_t len = 0;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
	MBEDTLS_ASN1_CHK_ADD(
	    len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	if (len > sig_size) {
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}

	memcpy(sig, p, len);
	*slen = len;

	return 0;
}

int rs_to_der(uint8_t rs[64], uint8_t *der, size_t der_size, size_t *olen) {
	int ret = -1;
	mbedtls_mpi r;
	mbedtls_mpi s;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if ((ret = read_raw_sig(rs, &r, &s)) != 0) {
		goto cleanup;
	}

	if ((ret = ecdsa_signature_to_asn1(&r, &s, der, der_size, olen))) {
		goto cleanup;
	}

	ret = 0;
cleanup:
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	return ret;
}

int pk_to_der(const uint8_t pk[64], uint8_t *der, size_t der_size, size_t *olen) {
	int ret = -1;
	uint8_t *p = der + der_size;
	size_t len = 0;
	size_t len_alg = 0;
	uint8_t point[65] = {0x04};
	memcpy(point + 1, pk, 64);

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&p, der, point, 65 * 8));

	MBEDTLS_ASN1_CHK_ADD(
	    len_alg, mbedtls_asn1_write_oid(&p, der, MBEDTLS_OID_EC_GRP_SECP256R1,
	                                    MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP256R1)));
	MBEDTLS_ASN1_CHK_ADD(
	    len_alg, mbedtls_asn1_write_oid(&p, der, MBEDTLS_OID_EC_ALG_UNRESTRICTED,
	                                    MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_ALG_UNRESTRICTED)));
	MBEDTLS_ASN1_CHK_ADD(len_alg, mbedtls_asn1_write_len(&p, der, len_alg));
	MBEDTLS_ASN1_CHK_ADD(
	    len_alg,
	    mbedtls_asn1_write_tag(&p, der, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	len += len_alg;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, der, len));
	MBEDTLS_ASN1_CHK_ADD(
	    len, mbedtls_asn1_write_tag(&p, der, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	*olen = len;
	memmove(der, p, len);

	return 0;
}

#pragma GCC diagnostic pop
