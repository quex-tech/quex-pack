// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "quote.h"
#include "test.h"
#include "utils.h"
#include <sgx_quote_3.h>
#include <stdlib.h>

#define INTEL_SGX_VENDOR_ID                                                                        \
	{                                                                                          \
		0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95,      \
		    0x7F, 0x06, 0x07                                                               \
	}

static void test_is_quote_header_well_formed_correct(void) {
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

static void test_is_quote_header_well_formed_wrong_version(void) {
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

static void test_is_quote_header_well_formed_wrong_att_key_type(void) {
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

static void test_is_quote_header_well_formed_wrong_att_key_data(void) {
	sgx_quote3_t quote = {.header = {.version = 3,
	                                 .att_key_type = SGX_QL_ALG_ECDSA_P256,
	                                 .att_key_data_0 = 1,
	                                 .vendor_id = INTEL_SGX_VENDOR_ID},
	                      .signature_data_len = 1024};

	must(!is_quote_header_well_formed(&quote),
	     "Quote with att_key_data_0=%u must not pass validation", quote.header.att_key_data_0);
}

static void test_is_quote_header_well_formed_wrong_vendor(void) {
	sgx_quote3_t quote = {
	    .header = {.version = 3,
	               .att_key_type = SGX_QL_ALG_ECDSA_P256,
	               .vendor_id = {0x92, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A,
	                             0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07}},
	    .signature_data_len = 1024};

	must(!is_quote_header_well_formed(&quote),
	     "Quote with wrong vendor must not pass validation");
}

static void test_is_quote_header_well_formed_wrong_signature_data_len(void) {
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

sgx_quote3_t *read_quote(const char *filename, size_t *size_out) {
	FILE *f = fopen(filename, "rb");
	if (!f) {
		perror("fopen");
		return NULL;
	}

	if (fseek(f, 0, SEEK_END) != 0) {
		perror("fseek");
		fclose(f);
		return NULL;
	}

	long pos = ftell(f);
	if (pos < 0) {
		perror("ftell");
		fclose(f);
		return NULL;
	}

	size_t size = (size_t)pos;
	rewind(f);

	sgx_quote3_t *buffer = malloc(size);
	if (!buffer) {
		perror("malloc");
		fclose(f);
		return NULL;
	}

	size_t read = fread(buffer, 1, size, f);
	if (read != (size_t)size) {
		perror("fread");
		free(buffer);
		fclose(f);
		return NULL;
	}

	fclose(f);

	if (size_out) {
		*size_out = (size_t)size;
	}

	return buffer;
}

static void test_verify_quote_valid(void) {
	size_t quote_len;
	sgx_quote3_t *quote = read_quote("./test_data/quote.dat", &quote_len);
	must(quote, "Could not read quote");

	mbedtls_x509_crt root_crt;
	mbedtls_x509_crt_init(&root_crt);

	const uint8_t root_crt_pem[] =
	    "-----BEGIN CERTIFICATE-----\n"
	    "MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw"
	    "aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv"
	    "cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ"
	    "BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG"
	    "A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0"
	    "aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT"
	    "AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7"
	    "1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB"
	    "uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ"
	    "MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50"
	    "ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV"
	    "Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI"
	    "KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg"
	    "AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n"
	    "-----END CERTIFICATE-----";

	int err = mbedtls_x509_crt_parse(&root_crt, root_crt_pem, sizeof root_crt_pem);
	must(err == 0, "Could not load root certificate. Got: %d", err);

	if (!quote || err) {
		goto cleanup;
	}

	must(verify_quote(quote, &root_crt) == 0, "Valid quote must pass verification");

cleanup:
	if (quote) {
		free(quote);
	}
	mbedtls_x509_crt_free(&root_crt);
}

static void test_quote(void) {
	test_is_quote_header_well_formed_correct();
	test_is_quote_header_well_formed_wrong_version();
	test_is_quote_header_well_formed_wrong_att_key_type();
	test_is_quote_header_well_formed_wrong_att_key_data();
	test_is_quote_header_well_formed_wrong_vendor();
	test_is_quote_header_well_formed_wrong_signature_data_len();
	test_verify_quote_valid();
}