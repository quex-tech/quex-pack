// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _TDX_H_
#define _TDX_H_

#include <tdx_attest.h>

struct tdx_iface {
	tdx_attest_error_t (*get_quote)(const tdx_report_data_t *p_tdx_report_data,
	                                const tdx_uuid_t att_key_id_list[], uint32_t list_size,
	                                tdx_uuid_t *p_att_key_id, uint8_t **pp_quote,
	                                uint32_t *p_quote_size, uint32_t flags);
	tdx_attest_error_t (*free_quote)(uint8_t *p_quote);
	tdx_attest_error_t (*get_report)(const tdx_report_data_t *p_tdx_report_data,
	                                 tdx_report_t *p_tdx_report);
};

#endif
