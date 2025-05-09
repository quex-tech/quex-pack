#ifndef _DER_H_
#define _DER_H_

#include <stddef.h>
#include <stdint.h>

int rs_to_der(const uint8_t rs[64], uint8_t *der, size_t der_size, size_t *olen);
int pk_to_der(const uint8_t pk[64], unsigned char *der, size_t der_size, size_t *olen);

#endif