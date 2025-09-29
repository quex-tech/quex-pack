#include "report.h"
#include "utils.h"
#include <sgx_quote_5.h>
#include <stdio.h>
#include <string.h>

static int passed_count;
static int failed_count;

#define must(c, ...)                                                                               \
	if (!(c)) {                                                                                \
		failed_count++;                                                                    \
		printf(__VA_ARGS__);                                                               \
		printf("\n");                                                                      \
	} else {                                                                                   \
		passed_count++;                                                                    \
	}

static void test_apply_zero_mask() {
	sgx_report2_t report = {0};
	memset(&report, 0x1a, sizeof report);

	sgx_report2_t zero_report = {0};

	td_key_request_mask_t zero_mask = {0};

	apply_mask(&report, &zero_mask);

	must(memcmp(&zero_report, &report, sizeof report) == 0, "Full mask must nullify report");
}

static void test_apply_full_mask() {
	sgx_report2_t original_report = {0};
	memset(&original_report, 0x1a, sizeof original_report);

	sgx_report2_t report = original_report;

	td_key_request_mask_t full_mask;
	memset(&full_mask, 0xff, sizeof full_mask);

	apply_mask(&report, &full_mask);

	must(memcmp(&original_report, &report, sizeof report) == 0,
	     "Full mask must not modify report");
}

static void test_apply_partial_mask() {
	sgx_report2_t report = {.report_mac_struct = {.report_type = {1},
	                                              .reserved1 = {2},
	                                              .cpu_svn = {.svn = {3, 4, 5, 6}},
	                                              .tee_tcb_info_hash = {.m = {7}},
	                                              .tee_info_hash = {.m = {8}},
	                                              .report_data = {.d = {9}},
	                                              .reserved2 = {10},
	                                              .mac = {11}},
	                        .reserved = {25}};
	tee_tcb_info_v1_5_t tee_tcb_info = {.valid = {12},
	                                    .tee_tcb_svn = {.tcb_svn = {13, 14, 15, 16}},
	                                    .mr_seam = {.m = {17}},
	                                    .mr_seam_signer = {.m = {18}},
	                                    .attributes = {.a = {19}},
	                                    .tee_tcb_svn2 = {.tcb_svn = {20, 21, 22, 23}},
	                                    .reserved = {24}};
	tee_info_v1_5_t tee_info = {.attributes = {.a = {26}},
	                            .xfam = {.a = {27}},
	                            .mr_td = {.m = {28}},
	                            .mr_config_id = {.m = {29}},
	                            .mr_owner = {.m = {30}},
	                            .mr_owner_config = {.m = {31}},
	                            .rt_mr = {{.m = {32}}, {.m = {33}}, {.m = {34}}, {.m = {35}}},
	                            .mr_servicetd = {.m = {36}},
	                            .reserved = {37}};
	memcpy(&report.tee_tcb_info, &tee_tcb_info, sizeof tee_tcb_info);
	memcpy(&report.tee_info, &tee_info, sizeof tee_info);

	td_key_request_mask_t mask = {.reportmacstruct_mask = 0b01010101,
	                              .tee_tcb_info_mask = 0b0000000101010101,
	                              .reserved_mask = 0b0,
	                              .tdinfo_base_mask = 0b0000010101010101,
	                              .tdinfo_extension_mask = 0b0};

	sgx_report2_t expected_report = {.report_mac_struct = {.report_type = {1},
	                                                       .reserved1 = {0},
	                                                       .cpu_svn = {.svn = {3, 4, 5, 6}},
	                                                       .tee_tcb_info_hash = {.m = {0}},
	                                                       .tee_info_hash = {.m = {8}},
	                                                       .report_data = {.d = {0}},
	                                                       .reserved2 = {10},
	                                                       .mac = {0}},
	                                 .reserved = {0}};
	tee_tcb_info_v1_5_t expected_tee_tcb_info = {.valid = {12},
	                                             .tee_tcb_svn = {.tcb_svn = {0}},
	                                             .mr_seam = {.m = {17}},
	                                             .mr_seam_signer = {.m = {0}},
	                                             .attributes = {.a = {19}},
	                                             .tee_tcb_svn2 = {.tcb_svn = {0, 21, 0, 23}},
	                                             .reserved = {0}};
	tee_info_v1_5_t expected_tee_info = {
	    .attributes = {.a = {26}},
	    .xfam = {.a = {0}},
	    .mr_td = {.m = {28}},
	    .mr_config_id = {.m = {0}},
	    .mr_owner = {.m = {30}},
	    .mr_owner_config = {.m = {0}},
	    .rt_mr = {{.m = {32}}, {.m = {0}}, {.m = {34}}, {.m = {0}}},
	    .mr_servicetd = {.m = {36}},
	    .reserved = {0}};
	memcpy(&expected_report.tee_tcb_info, &expected_tee_tcb_info, sizeof expected_tee_tcb_info);
	memcpy(&expected_report.tee_info, &expected_tee_info, sizeof expected_tee_info);

	apply_mask(&report, &mask);

	must(memcmp(&expected_report.report_mac_struct, &report.report_mac_struct,
	            sizeof report.report_mac_struct) == 0,
	     "Mask must modify report_mac_struct correctly");
	must(memcmp(&expected_report.tee_tcb_info, &report.tee_tcb_info,
	            sizeof report.tee_tcb_info) == 0,
	     "Mask must modify tee_tcb_info correctly");
	must(memcmp(&expected_report.reserved, &report.reserved, sizeof report.reserved) == 0,
	     "Mask must modify reserved correctly");
	must(memcmp(&expected_report.tee_info, &report.tee_info, sizeof report.tee_info) == 0,
	     "Mask must modify tee_info correctly");
	must(memcmp(&expected_report, &report, sizeof report) == 0,
	     "Mask must modify report correctly");
}

int main() {
	test_apply_zero_mask();
	test_apply_full_mask();
	test_apply_partial_mask();

	printf("Passed: %d, Failed: %d\n", passed_count, failed_count);

	return failed_count;
}