// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#ifndef _REPORT_H_
#define _REPORT_H_

#include "types.h"
#include <sgx_report2.h>

void apply_mask(sgx_report2_t *report, const struct td_key_request_mask *mask);

#endif
