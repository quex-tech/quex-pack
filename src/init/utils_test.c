// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "test.h"
#include "utils.h"
#include <string.h>

void test_utils(void);

static void test_write_hex_known_vector(void) {
	uint8_t bytes[] = {0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff};
	char out[sizeof_array(bytes) * 2 + 1];

	write_hex(bytes, sizeof_array(bytes), out, sizeof out);

	const char expected[] = "00017f80feff";
	must(memcmp(out, expected, sizeof_array(bytes) * 2) == 0,
	     "write_hex must format lowercase hex with leading zeros");
}

static void test_read_hex_known_vector(void) {
	const char hex[] = "deadbeef00ff";
	uint8_t out[6] = {0};
	const uint8_t expected[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0xff};

	must(read_hex(hex, out, sizeof_array(out)) == 0, "read_hex must succeed on valid input");
	must(memcmp(out, expected, sizeof expected) == 0, "read_hex must parse correctly");
}

static void test_hex_roundtrip(void) {
	uint8_t in[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	char hex[sizeof_array(in) * 2 + 1];
	uint8_t out[sizeof_array(in)] = {0};

	write_hex(in, sizeof_array(in), hex, sizeof hex);
	must(read_hex(hex, out, sizeof_array(out)) == 0,
	     "read_hex must accept output of write_hex");
	must(memcmp(in, out, sizeof_array(in)) == 0,
	     "Roundtrip write_hex/read_hex must preserve bytes");
}

static void test_read_hex_invalid_len(void) {
	const char hex[] = "abc";
	uint8_t out[2] = {0};

	must(read_hex(hex, out, sizeof_array(out)) == -1, "read_hex must fail on odd-length hex");
}

static void test_read_hex_invalid_char(void) {
	const char hex[] = "0x";
	uint8_t out[1] = {0};

	must(read_hex(hex, out, sizeof_array(out)) == -1,
	     "read_hex must fail on non-hex characters");
}

void test_utils(void) {
	test_write_hex_known_vector();
	test_read_hex_known_vector();
	test_hex_roundtrip();
	test_read_hex_invalid_len();
	test_read_hex_invalid_char();
}
