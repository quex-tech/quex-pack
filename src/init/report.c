// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "report.h"
#include "utils.h"
#include <sgx_quote_5.h>
#include <stddef.h>
#include <string.h>

struct tee_tcb_svn_t_parsed {
	uint8_t tdx_module_svn_minor;
	uint8_t tdx_module_svn_major;
	uint8_t seam_last_patch_svn;
	uint8_t reserved[13];
};

static inline void do_mask(uint16_t mask, unsigned bit, void *out_mem, size_t mem_len) {
	if (!(mask & (1u << bit))) {
		memset(out_mem, 0, mem_len);
	}
}

#define mask_field(m, b, p, t, f) do_mask(m, b, (uint8_t *)p + offsetof(t, f), sizeof_field(t, f))
#define mask_exp(m, b, e) do_mask(m, b, &(e), sizeof e)

static void apply_report_mac_struct_mask(sgx_report2_mac_struct_t *mac, uint8_t mask) {
	mask_exp(mask, 0, mac->report_type);
	mask_exp(mask, 1, mac->reserved1);
	mask_exp(mask, 2, mac->cpu_svn);
	mask_exp(mask, 3, mac->tee_tcb_info_hash);
	mask_exp(mask, 4, mac->tee_info_hash);
	mask_exp(mask, 5, mac->report_data);
	mask_exp(mask, 6, mac->reserved2);
	mask_exp(mask, 7, mac->mac);
}

static void apply_tee_tcb_info_mask(uint8_t *restrict tee_tcb_info, uint16_t mask) {
	mask_field(mask, 0, tee_tcb_info, tee_tcb_info_v1_5_t, valid);
	mask_field(mask, 1, tee_tcb_info, tee_tcb_info_v1_5_t, tee_tcb_svn);
	mask_field(mask, 2, tee_tcb_info, tee_tcb_info_v1_5_t, mr_seam);
	mask_field(mask, 3, tee_tcb_info, tee_tcb_info_v1_5_t, mr_seam_signer);
	mask_field(mask, 4, tee_tcb_info, tee_tcb_info_v1_5_t, attributes);

	uint8_t *svn2 = tee_tcb_info + offsetof(tee_tcb_info_v1_5_t, tee_tcb_svn2);
	mask_field(mask, 5, svn2, struct tee_tcb_svn_t_parsed, tdx_module_svn_minor);
	mask_field(mask, 6, svn2, struct tee_tcb_svn_t_parsed, tdx_module_svn_major);
	mask_field(mask, 7, svn2, struct tee_tcb_svn_t_parsed, seam_last_patch_svn);
	mask_field(mask, 8, svn2, struct tee_tcb_svn_t_parsed, reserved);

	mask_field(mask, 9, tee_tcb_info, tee_tcb_info_v1_5_t, reserved);
}

static void apply_tee_info_mask(uint8_t *restrict tee_info, uint16_t base_mask,
                                uint8_t extension_mask) {
	mask_field(base_mask, 0, tee_info, tee_info_v1_5_t, attributes);
	mask_field(base_mask, 1, tee_info, tee_info_v1_5_t, xfam);
	mask_field(base_mask, 2, tee_info, tee_info_v1_5_t, mr_td);
	mask_field(base_mask, 3, tee_info, tee_info_v1_5_t, mr_config_id);
	mask_field(base_mask, 4, tee_info, tee_info_v1_5_t, mr_owner);
	mask_field(base_mask, 5, tee_info, tee_info_v1_5_t, mr_owner_config);
	mask_field(base_mask, 6, tee_info, tee_info_v1_5_t, rt_mr[0]);
	mask_field(base_mask, 7, tee_info, tee_info_v1_5_t, rt_mr[1]);
	mask_field(base_mask, 8, tee_info, tee_info_v1_5_t, rt_mr[2]);
	mask_field(base_mask, 9, tee_info, tee_info_v1_5_t, rt_mr[3]);
	mask_field(base_mask, 10, tee_info, tee_info_v1_5_t, mr_servicetd);
	mask_field(extension_mask, 0, tee_info, tee_info_v1_5_t, reserved);
}

void apply_mask(sgx_report2_t *report, const struct td_key_request_mask *mask) {
	_Static_assert(sizeof(tee_tcb_info_v1_5_t) == sizeof report->tee_tcb_info, "Size mismatch");
	_Static_assert(sizeof(tee_info_v1_5_t) == sizeof report->tee_info, "Size mismatch");
	_Static_assert(sizeof(tee_tcb_svn_t) == sizeof(struct tee_tcb_svn_t_parsed),
	               "Size mismatch");

	apply_report_mac_struct_mask(&report->report_mac_struct, mask->reportmacstruct_mask);
	apply_tee_tcb_info_mask(report->tee_tcb_info, mask->tee_tcb_info_mask);

	mask_exp(mask->reserved_mask, 0, report->reserved);

	apply_tee_info_mask(report->tee_info, mask->tdinfo_base_mask, mask->tdinfo_extension_mask);
}

#undef mask_field
#undef mask_exp
