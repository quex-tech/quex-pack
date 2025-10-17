// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "test.h"
#include "der_test.h"
#include "ec_test.h"
#include "integrity_crypt_test.h"
#include "key_test.h"
#include "mkfs_test.h"
#include "mount_test.h"
#include "quote_test.h"
#include "report_test.h"
#include "utils_test.h"

int main(void) {
	test_der();
	test_ec();
	test_integrity_crypt();
	test_key();
	test_mkfs();
	test_mount();
	test_quote();
	test_report();
	test_utils();

	printf("Passed: %d, Failed: %d\n", passed_count, failed_count);

	return failed_count;
}
