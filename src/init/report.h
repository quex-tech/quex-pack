// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef REPORT_H
#define REPORT_H

#include "types.h"
#include <sgx_report2.h>

void apply_mask(sgx_report2_t *report, const struct td_key_request_mask *mask);

#endif
