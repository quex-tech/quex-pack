// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef TYPES_H
#define TYPES_H

#include <sgx_quote_3.h>
#include <sgx_report2.h>

#define QUEX_CT_LEN 128

#pragma pack(push, 1)

struct td_key_request_mask {
	uint8_t reportmacstruct_mask;
	uint16_t tee_tcb_info_mask;
	uint8_t reserved_mask;
	uint16_t tdinfo_base_mask;
	uint8_t tdinfo_extension_mask;
};

struct td_key_request {
	struct td_key_request_mask mask;
	sgx_report2_t tdreport;
};

struct td_response_msg {
	struct td_key_request_mask mask;
	sgx_report2_t tdreport;
	uint8_t ciphertext[QUEX_CT_LEN];
};

#pragma pack(pop)

#endif
