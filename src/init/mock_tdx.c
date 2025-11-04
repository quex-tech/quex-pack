// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "mock_tdx.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tdx_attest.h>

static uint8_t *current_quote = NULL;
static uint32_t current_quote_len = 0;
static tdx_report_t *current_report = NULL;

void set_quote(uint8_t *quote, uint32_t quote_len) {
	current_quote = quote;
	current_quote_len = quote_len;
}

void set_report(tdx_report_t *report) { current_report = report; }

tdx_attest_error_t __wrap_tdx_att_get_quote(const tdx_report_data_t *p_tdx_report_data,
                                            const tdx_uuid_t att_key_id_list[], uint32_t list_size,
                                            tdx_uuid_t *p_att_key_id, uint8_t **pp_quote,
                                            uint32_t *p_quote_size, uint32_t flags);
tdx_attest_error_t __wrap_tdx_att_free_quote(const uint8_t *p_quote);
tdx_attest_error_t __wrap_tdx_att_get_report(const tdx_report_data_t *p_tdx_report_data,
                                             tdx_report_t *p_tdx_report);

// cppcheck-suppress unusedFunction
tdx_attest_error_t __wrap_tdx_att_get_quote(const tdx_report_data_t *p_tdx_report_data,
                                            const tdx_uuid_t att_key_id_list[], uint32_t list_size,
                                            tdx_uuid_t *p_att_key_id, uint8_t **pp_quote,
                                            uint32_t *p_quote_size, uint32_t flags) {
	(void)p_tdx_report_data;
	(void)att_key_id_list;
	(void)list_size;
	(void)flags;
	if (p_att_key_id) {
		memset(p_att_key_id, 0, sizeof *p_att_key_id);
	}

	*p_quote_size = current_quote_len;
	*pp_quote = current_quote;

	return TDX_ATTEST_SUCCESS;
}

// cppcheck-suppress unusedFunction
tdx_attest_error_t __wrap_tdx_att_free_quote(const uint8_t *p_quote) {
	(void)p_quote;
	return TDX_ATTEST_SUCCESS;
}

// cppcheck-suppress unusedFunction
tdx_attest_error_t __wrap_tdx_att_get_report(const tdx_report_data_t *p_tdx_report_data,
                                             tdx_report_t *p_tdx_report) {
	(void)p_tdx_report_data;
	if (current_report == NULL) {
		return TDX_ATTEST_ERROR_UNEXPECTED;
	}
	memcpy(p_tdx_report, current_report, sizeof *current_report);
	return TDX_ATTEST_SUCCESS;
}
