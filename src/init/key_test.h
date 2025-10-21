// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "key.h"
#include "mock_network.h"
#include "mock_tdx.h"
#include "test.h"
#include "types.h"
#include "utils.h"
#include <string.h>

static int no_entropy(void *data, uint8_t *output, size_t len) {
	(void)data;
	memset(output, 0, len);
	return 0;
}

static void test_get_keys(void) {
	uint8_t *key_msg_blob = NULL;
	size_t key_msg_len = 0;
	must(read_bin_file("./test_data/key_msg.dat", &key_msg_blob, &key_msg_len) == 0,
	     "must read key_msg");

	uint8_t *quote_blob = NULL;
	size_t quote_len = 0;
	must(read_bin_file("./test_data/quote.dat", &quote_blob, &quote_len) == 0,
	     "must read quote");

	if (!key_msg_blob || !quote_blob) {
		goto cleanup;
	}

	mock_network_send(&mock_network_incoming, key_msg_blob, key_msg_len);
	mock_network_send(&mock_network_incoming, quote_blob, quote_len);

	uint8_t sk[32] = {0};
	uint8_t pk[64] = {0};

	int err = get_keys("04030000c70000",
	                   "231c8240fb43d8ee81a813a3a3fb05e3"
	                   "b9f1ae9064fe4d8629cf691a58d74112",
	                   "./test_data/root.pem", no_entropy, sk, pk);
	must(err == 0, "get_keys must succeed");

	char sk_hex[2 * sizeof sk + 1] = {0};
	write_hex(sk, sizeof sk, sk_hex);
	must(strcmp(sk_hex, "1ce6ca8f269a7b09defe608e1cd92959"
	                    "f752be0c9dd1cd5424e783d8c4f7d1ab") == 0,
	     "sk must be expected");

	char pk_hex[2 * sizeof pk + 1] = {0};
	write_hex(pk, sizeof pk, pk_hex);
	must(strcmp(pk_hex, "9f4681953cb9b53e1a6c90f3e64b5f38"
	                    "41aff3376051168a70bc9500fcf495ec"
	                    "079df19bde642a7a5692ca20a80eaad0"
	                    "f023966ea372e7f15ae6020f532d3ee7") == 0,
	     "pk must be expected");

	struct td_key_request key_request = {0};
	must(mock_network_recv(&mock_network_outgoing, &key_request, sizeof key_request) ==
	         sizeof key_request,
	     "must send key request");

	uint8_t key_request_mask[sizeof key_request.mask] = {0};
	memcpy(key_request_mask, &key_request.mask, sizeof key_request.mask);
	char key_request_mask_hex[2 * sizeof key_request.mask + 1] = {0};
	write_hex(key_request_mask, sizeof key_request_mask, key_request_mask_hex);

	must(strcmp(key_request_mask_hex, "04030000c70000") == 0, "must send correct mask");

cleanup:
	free(key_msg_blob);
	free(quote_blob);
	mock_network_reset(&mock_network_incoming);
	mock_network_reset(&mock_network_outgoing);
}

static void test_key(void) { test_get_keys(); }
