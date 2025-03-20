#ifndef TSL_H_
#define TSL_H_

#include <stdint.h>

void tsl_recv_set_tsl(uint8_t *payload, uint32_t payload_len);
void tsl_send_report_tsl();

#endif
