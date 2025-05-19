#ifndef _TYPES_H_
#define _TYPES_H_

#include <sgx_quote_3.h>
#include <sgx_report2.h>

#define QUEX_CT_LEN 128

#pragma pack(push, 1)

typedef struct _td_key_request_mask_t {
	uint8_t reportmacstruct_mask;
	uint16_t tee_tcb_info_mask;
	uint8_t reserved_mask;
	uint16_t tdinfo_base_mask;
	uint8_t tdinfo_extension_mask;
} td_key_request_mask_t;

typedef struct _td_key_request_t {
	td_key_request_mask_t mask;
	sgx_report2_t tdreport;
} td_key_request_t;

typedef struct _td_response_msg_t {
	td_key_request_mask_t mask;
	sgx_report2_t tdreport;
	uint8_t ciphertext[QUEX_CT_LEN];
} td_response_msg_t;

typedef struct _quoted_td_key_response_t {
	td_response_msg_t msg;
	sgx_quote3_t quote;
} quoted_td_key_response_t;

#pragma pack(pop)

#endif
