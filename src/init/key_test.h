// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "key.h"
#include "tdx.h"
#include "test.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_PORT 24516

static int read_bin_file(const char *path, uint8_t **out, size_t *out_len) {
	FILE *f = fopen(path, "rb");
	if (!f) {
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	long sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return -1;
	}
	rewind(f);
	uint8_t *buf = (uint8_t *)malloc((size_t)sz);
	if (!buf) {
		fclose(f);
		return -1;
	}
	size_t n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	if (n != (size_t)sz) {
		free(buf);
		return -1;
	}
	*out = buf;
	if (out_len) {
		*out_len = (size_t)sz;
	}
	return 0;
}

static tdx_attest_error_t mock_get_quote(const tdx_report_data_t *p_tdx_report_data,
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
	*pp_quote = (uint8_t *)malloc(*p_quote_size);
	memset(*pp_quote, 0xAB, *p_quote_size);
	return TDX_ATTEST_SUCCESS;
}

static tdx_attest_error_t mock_free_quote(uint8_t *p_quote) {
	free(p_quote);
	return TDX_ATTEST_SUCCESS;
}

static tdx_attest_error_t mock_get_report(const tdx_report_data_t *p_tdx_report_data,
                                          tdx_report_t *p_tdx_report) {
	(void)p_tdx_report_data;
	size_t size = 0;
	uint8_t *report = NULL;
	read_bin_file("./test_data/report.dat", &report, &size);
	memcpy(p_tdx_report, report, size);
	return TDX_ATTEST_SUCCESS;
}

struct get_keys_thread_args {
	uint8_t sk_out[32];
	uint8_t pk_out[64];
	int ret_out;
};

static int no_entropy(void *data, uint8_t *output, size_t len) {
	(void)data;
	memset(output, 0, len);
	return 0;
}

static void *get_keys_thread_main(void *arg) {
	struct get_keys_thread_args *a = arg;
	struct tdx_iface mock_tdx_ops = {
	    .get_quote = mock_get_quote,
	    .free_quote = mock_free_quote,
	    .get_report = mock_get_report,
	};
	a->ret_out = get_keys(
	    "04030000c70000", "231c8240fb43d8ee81a813a3a3fb05e3b9f1ae9064fe4d8629cf691a58d74112",
	    "./test_data/root.pem", &mock_tdx_ops, no_entropy, a->sk_out, a->pk_out);
	return NULL;
}

static int connect_sock(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TEST_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static void test_get_keys(void) {
	int fd = 0;

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

	struct get_keys_thread_args args = {
	    .sk_out = {0},
	    .ret_out = -1,
	};

	pthread_t th;
	int perr = pthread_create(&th, NULL, get_keys_thread_main, &args);
	must(perr == 0, "pthread_create must succeed");
	if (perr) {
		goto cleanup;
	}

	usleep(150 * 1000);

	fd = connect_sock();
	must(fd > 0, "connect_sock must succeed");
	if (fd <= 0) {
		goto cleanup;
	}

	send(fd, key_msg_blob, key_msg_len, 0);
	send(fd, quote_blob, quote_len, 0);

	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		must(0, "clock_gettime must succeed");
		goto cleanup;
	}

	ts.tv_sec += 5;

	if (pthread_timedjoin_np(th, NULL, &ts) != 0) {
		must(0, "pthread_timedjoin_np must succeed");
		goto cleanup;
	}

	must(args.ret_out == 0, "get_keys must return success");
cleanup:
	free(key_msg_blob);
	free(quote_blob);
	if (fd > 0) {
		close(fd);
	}
}

static void test_key(void) { test_get_keys(); }
