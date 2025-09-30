// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "quote.h"
#include "test.h"

#define INTEL_SGX_VENDOR_ID                                                                        \
	{                                                                                          \
		0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95,      \
		    0x7F, 0x06, 0x07                                                               \
	}

static void test_is_quote_header_well_formed_correct() {
	uint32_t signature_data_lengths[3] = {584, 1024, 16384};

	sgx_quote3_t quote = {.header = {.version = 3,
	                                 .att_key_type = SGX_QL_ALG_ECDSA_P256,
	                                 .vendor_id = INTEL_SGX_VENDOR_ID}};

	for (size_t i = 0; i < sizeof_array(signature_data_lengths); i++) {
		quote.signature_data_len = signature_data_lengths[i];
		must(is_quote_header_well_formed(&quote),
		     "Correct quote with signature_data_len=%u must pass validation",
		     quote.signature_data_len);
	}
}

static void test_is_quote_header_well_formed_wrong_version() {
	uint16_t versions[] = {0, 1, 2, 4, 5};

	sgx_quote3_t quote = {
	    .header = {.att_key_type = SGX_QL_ALG_ECDSA_P256, .vendor_id = INTEL_SGX_VENDOR_ID},
	    .signature_data_len = 1024};

	for (size_t i = 0; i < sizeof_array(versions); i++) {
		quote.header.version = versions[i];
		must(!is_quote_header_well_formed(&quote),
		     "Quote with version=%u must not pass validation", quote.header.version);
	}
}

static void test_is_quote_header_well_formed_wrong_att_key_type() {
	uint16_t key_types[] = {SGX_QL_ALG_EPID, SGX_QL_ALG_RESERVED_1, SGX_QL_ALG_ECDSA_P384,
	                        SGX_QL_ALG_MAX, 5};

	sgx_quote3_t quote = {.header = {.version = 3, .vendor_id = INTEL_SGX_VENDOR_ID},
	                      .signature_data_len = 1024};

	for (size_t i = 0; i < sizeof_array(key_types); i++) {
		quote.header.att_key_type = key_types[i];
		must(!is_quote_header_well_formed(&quote),
		     "Quote with att_key_type=%u must not pass validation",
		     quote.header.att_key_type);
	}
}

static void test_is_quote_header_well_formed_wrong_att_key_data() {
	sgx_quote3_t quote = {.header = {.version = 3,
	                                 .att_key_type = SGX_QL_ALG_ECDSA_P256,
	                                 .att_key_data_0 = 1,
	                                 .vendor_id = INTEL_SGX_VENDOR_ID},
	                      .signature_data_len = 1024};

	must(!is_quote_header_well_formed(&quote),
	     "Quote with att_key_data_0=%u must not pass validation", quote.header.att_key_data_0);
}

static void test_is_quote_header_well_formed_wrong_vendor() {
	sgx_quote3_t quote = {
	    .header = {.version = 3,
	               .att_key_type = SGX_QL_ALG_ECDSA_P256,
	               .vendor_id = {0x92, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A,
	                             0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07}},
	    .signature_data_len = 1024};

	must(!is_quote_header_well_formed(&quote),
	     "Quote with wrong vendor must not pass validation");
}

static void test_is_quote_header_well_formed_wrong_signature_data_len() {
	uint32_t signature_data_lengths[3] = {0, 583, 16385};

	sgx_quote3_t quote = {.header = {.version = 3,
	                                 .att_key_type = SGX_QL_ALG_ECDSA_P256,
	                                 .vendor_id = INTEL_SGX_VENDOR_ID}};

	for (size_t i = 0; i < sizeof_array(signature_data_lengths); i++) {
		quote.signature_data_len = signature_data_lengths[i];
		must(!is_quote_header_well_formed(&quote),
		     "Quote with signature_data_len=%u must not pass validation",
		     quote.signature_data_len);
	}
}

static void test_quote() {
	test_is_quote_header_well_formed_correct();
	test_is_quote_header_well_formed_wrong_version();
	test_is_quote_header_well_formed_wrong_att_key_type();
	test_is_quote_header_well_formed_wrong_att_key_data();
	test_is_quote_header_well_formed_wrong_vendor();
	test_is_quote_header_well_formed_wrong_signature_data_len();
}