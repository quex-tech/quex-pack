#ifndef _EC_H_
#define _EC_H_

#include <mbedtls/ecp.h>

int read_raw_pk(mbedtls_ecp_group *grp, const uint8_t raw[64], mbedtls_ecp_point *pk);
int write_raw_pk(mbedtls_ecp_group *grp, mbedtls_ecp_point *pk, uint8_t out[64]);
int read_raw_sig(const uint8_t raw[64], mbedtls_mpi *r, mbedtls_mpi *s);

#endif
