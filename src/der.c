#include "ec.h"
#include <mbedtls/asn1write.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <stdint.h>
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

// copied from vendor/mbedtls/library/ecdsa.c
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

#pragma GCC diagnostic pop
