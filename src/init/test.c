// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "test.h"
#include "der_test.h"
#include "ec_test.h"
#include "quote_test.h"
#include "report_test.h"

int main() {
	test_report();
	test_quote();
	test_ec();
	test_der();

	printf("Passed: %d, Failed: %d\n", passed_count, failed_count);

	return failed_count;
}