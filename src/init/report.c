// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "report.h"
#include <string.h>

void apply_mask(sgx_report2_t *report, td_key_request_mask_t *mask) {
	if (!(mask->reportmacstruct_mask & 1)) {
		memset(&(report->report_mac_struct.report_type), 0, 4);
	}
	if (!(mask->reportmacstruct_mask & (1 << 1))) {
		memset(&(report->report_mac_struct.reserved1), 0, 12);
	}
	if (!(mask->reportmacstruct_mask & (1 << 2))) {
		memset(&(report->report_mac_struct.cpu_svn), 0, 16);
	}
	if (!(mask->reportmacstruct_mask & (1 << 3))) {
		memset(&(report->report_mac_struct.tee_tcb_info_hash), 0, 48);
	}
	if (!(mask->reportmacstruct_mask & (1 << 4))) {
		memset(&(report->report_mac_struct.tee_info_hash), 0, 48);
	}
	if (!(mask->reportmacstruct_mask & (1 << 5))) {
		memset(&(report->report_mac_struct.report_data), 0, 64);
	}
	if (!(mask->reportmacstruct_mask & (1 << 6))) {
		memset(&(report->report_mac_struct.reserved2), 0, 32);
	}
	if (!(mask->reportmacstruct_mask & (1 << 7))) {
		memset(&(report->report_mac_struct.mac), 0, 32);
	}

	if (!(mask->tee_tcb_info_mask & 1)) {
		memset(&(report->tee_tcb_info), 0, 8);
	}
	if (!((mask->tee_tcb_info_mask >> 1) & 1)) {
		memset(&(report->tee_tcb_info), 8, 16);
	}
	if (!((mask->tee_tcb_info_mask >> 2) & 1)) {
		memset(&(report->tee_tcb_info), 24, 48);
	}
	if (!((mask->tee_tcb_info_mask >> 3) & 1)) {
		memset(&(report->tee_tcb_info), 72, 48);
	}
	if (!((mask->tee_tcb_info_mask >> 4) & 1)) {
		memset(&(report->tee_tcb_info), 120, 8);
	}
	if (!((mask->tee_tcb_info_mask >> 5) & 1)) {
		memset(&(report->tee_tcb_info), 128, 1);
	}
	if (!((mask->tee_tcb_info_mask >> 6) & 1)) {
		memset(&(report->tee_tcb_info), 129, 1);
	}
	if (!((mask->tee_tcb_info_mask >> 7) & 1)) {
		memset(&(report->tee_tcb_info), 130, 1);
	}
	if (!((mask->tee_tcb_info_mask >> 8) & 1)) {
		memset(&(report->tee_tcb_info), 131, 13);
	}
	if (!((mask->tee_tcb_info_mask >> 9) & 1)) {
		memset(&(report->tee_tcb_info), 144, 95);
	}

	if (!(mask->reserved_mask & 1)) {
		memset(&(report->reserved), 0, SGX_REPORT2_RESERVED_BYTES);
	}

	if (!(mask->tdinfo_base_mask & 1)) {
		memset(&(report->tee_info), 0, 8);
	}
	if (!((mask->tdinfo_base_mask >> 1) & 1)) {
		memset(&(report->tee_info), 8, 8);
	}
	if (!((mask->tdinfo_base_mask >> 2) & 1)) {
		memset(&(report->tee_info), 16, 48);
	}
	if (!((mask->tdinfo_base_mask >> 3) & 1)) {
		memset(&(report->tee_info), 64, 48);
	}
	if (!((mask->tdinfo_base_mask >> 4) & 1)) {
		memset(&(report->tee_info), 112, 48);
	}
	if (!((mask->tdinfo_base_mask >> 5) & 1)) {
		memset(&(report->tee_info), 160, 48);
	}
	if (!((mask->tdinfo_base_mask >> 6) & 1)) {
		memset(&(report->tee_info), 208, 48);
	}
	if (!((mask->tdinfo_base_mask >> 7) & 1)) {
		memset(&(report->tee_info), 256, 48);
	}
	if (!((mask->tdinfo_base_mask >> 8) & 1)) {
		memset(&(report->tee_info), 304, 48);
	}
	if (!((mask->tdinfo_base_mask >> 9) & 1)) {
		memset(&(report->tee_info), 352, 48);
	}
	if (!((mask->tdinfo_base_mask >> 10) & 1)) {
		memset(&(report->tee_info), 400, 48);
	}
	if (!(mask->tdinfo_extension_mask & 1)) {
		memset(&(report->tee_info), 448, 64);
	}
}
