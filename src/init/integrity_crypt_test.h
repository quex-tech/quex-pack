// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "integrity_crypt.h"
#include "test.h"
#include <string.h>

static void test_parse_crypt_spec_ok() {
	char valid[] = "/dev/vdc1:root-crypt";
	struct crypt_spec spec = {0};

	must(parse_crypt_spec(valid, &spec) == 0, "parse_crypt_spec must succeed");
	must(strcmp(spec.dev, "/dev/vdc1") == 0, "dev must be /dev/vdc1");
	must(strcmp(spec.name, "root-crypt") == 0, "name must be root-crypt");
}

static void test_parse_crypt_spec_invalid() {
	struct crypt_spec spec = {0};
	char no_name[] = "/dev/vdc1";

	must(parse_crypt_spec(NULL, &spec) == -1, "NULL input must fail");
	must(parse_crypt_spec(no_name, &spec) == -1, "missing name must fail");

	char valid[] = "/dev/vdc1:root";
	must(parse_crypt_spec(valid, NULL) == -1, "NULL output must fail");
}

static void test_parse_integrity_spec_ok() {
	char valid[] = "/dev/vdd1:root-int";
	struct integrity_spec spec = {0};

	must(parse_integrity_spec(valid, &spec) == 0, "parse_integrity_spec must succeed");
	must(strcmp(spec.dev, "/dev/vdd1") == 0, "dev must be /dev/vdd1");
	must(strcmp(spec.name, "root-int") == 0, "name must be root-int");
}

static void test_parse_integrity_spec_invalid() {
	struct integrity_spec spec = {0};
	char no_name[] = "/dev/vdd1";

	must(parse_integrity_spec(NULL, &spec) == -1, "NULL input must fail");
	must(parse_integrity_spec(no_name, &spec) == -1, "missing name must fail");

	char valid[] = "/dev/vdd1:int";
	must(parse_integrity_spec(valid, NULL) == -1, "NULL output must fail");
}

static void test_integrity_crypt() {
	test_parse_crypt_spec_ok();
	test_parse_crypt_spec_invalid();
	test_parse_integrity_spec_ok();
	test_parse_integrity_spec_invalid();
}
