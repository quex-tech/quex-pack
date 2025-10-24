// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef TEST_H
#define TEST_H

#include <stdio.h> // IWYU pragma: keep

extern int passed_count;
extern int failed_count;

#define must(c, ...)                                                                               \
	do {                                                                                       \
		if (!(c)) {                                                                        \
			failed_count++;                                                            \
			printf(__VA_ARGS__);                                                       \
			printf("\n");                                                              \
		} else {                                                                           \
			passed_count++;                                                            \
		}                                                                                  \
	} while (0)

#endif
