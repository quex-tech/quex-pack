#ifndef ___wrap_tdx_att_TDX_H
#define _MOCK_TDX_H

#include "test.h"
#include <stdlib.h>
#include <string.h>
#include <tdx_attest.h>

tdx_attest_error_t __wrap_tdx_att_get_quote(const tdx_report_data_t *p_tdx_report_data,
                                            const tdx_uuid_t att_key_id_list[], uint32_t list_size,
                                            tdx_uuid_t *p_att_key_id, uint8_t **pp_quote,
                                            uint32_t *p_quote_size, uint32_t flags);
tdx_attest_error_t __wrap_tdx_att_free_quote(uint8_t *p_quote);
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
	*p_quote_size = 4;
	*pp_quote = malloc(*p_quote_size);
	memset(*pp_quote, 0xAB, *p_quote_size);
	return TDX_ATTEST_SUCCESS;
}

// cppcheck-suppress unusedFunction
tdx_attest_error_t __wrap_tdx_att_free_quote(uint8_t *p_quote) {
	free(p_quote);
	return TDX_ATTEST_SUCCESS;
}

// cppcheck-suppress unusedFunction
tdx_attest_error_t __wrap_tdx_att_get_report(const tdx_report_data_t *p_tdx_report_data,
                                             tdx_report_t *p_tdx_report) {
	(void)p_tdx_report_data;
	size_t size = 0;
	uint8_t *report = NULL;
	int err = read_bin_file("./test_data/report.dat", &report, &size);
	if (err) {
		return TDX_ATTEST_ERROR_UNEXPECTED;
	}
	memcpy(p_tdx_report, report, size);
	return TDX_ATTEST_SUCCESS;
}

#endif
