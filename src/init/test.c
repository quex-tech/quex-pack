// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies

#include "test.h"
#include <stdio.h>

int passed_count;
int failed_count;

void test_der(void);
void test_ec(void);
void test_integrity_crypt(void);
void test_key(void);
void test_mkfs(void);
void test_mount(void);
void test_quote(void);
void test_report(void);
void test_utils(void);

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
