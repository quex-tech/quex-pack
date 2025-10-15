// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _TEST_H_
#define _TEST_H_

#include <stdio.h>

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

#endif