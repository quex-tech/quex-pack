#ifndef MOCK_TDX_H
#define MOCK_TDX_H

#include <stdint.h>
#include <tdx_attest.h>

void set_quote(uint8_t *quote, uint32_t quote_len);
void set_report(tdx_report_t *report);

#endif
