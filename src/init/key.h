#ifndef _KEY_H_
#define _KEY_H_

#include <stdint.h>

int get_sk(uint8_t sk[32], const char *key_request_mask_hex, const char *vault_mr_enclave_hex);

#endif