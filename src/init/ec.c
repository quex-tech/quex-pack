#include "utils.h"
#include <mbedtls/ecp.h>
#include <string.h>

int read_raw_pk(mbedtls_ecp_group *grp, const uint8_t raw[64], mbedtls_ecp_point *pk) {
	uint8_t uncompressed[65] = {0x04};
	memcpy(uncompressed + 1, raw, 64);
	return mbedtls_ecp_point_read_binary(grp, pk, uncompressed, sizeof(uncompressed));
}

int write_raw_pk(mbedtls_ecp_group *grp, mbedtls_ecp_point *pk, uint8_t out[64]) {
	int ret;
	uint8_t uncompressed[65] = {0x04};
	size_t olen;
	if ((ret = mbedtls_ecp_point_write_binary(grp, pk, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
	                                          uncompressed, sizeof(uncompressed))) != 0) {
		trace("mbedtls_ecp_point_write_binary failed: %d\n", ret);
		return ret;
	}
	memcpy(out, uncompressed + 1, 64);
	return 0;
}

int read_raw_sig(const uint8_t raw[64], mbedtls_mpi *r, mbedtls_mpi *s) {
	int ret;

	if ((ret = mbedtls_mpi_read_binary(r, raw, 32)) != 0) {
		trace("mbedtls_mpi_read_binary(r) failed: %d\n", ret);
		return ret;
	}

	if ((ret = mbedtls_mpi_read_binary(s, raw + 32, 32)) != 0) {
		trace("mbedtls_mpi_read_binary(s) failed: %d\n", ret);
		return ret;
	}

	return 0;
}