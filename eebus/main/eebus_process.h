#ifndef EEBUS_PROCESS_H_
#define EEBUS_PROCESS_H_

#include <stdint.h>
#include "src/common/eebus_errors.h"

#define EEBUS_VENDOR            "solax"
#define EEBUS_BRAND             "brand"
#define EEBUS_TYPE              "pocket"
#define EEBUS_MODEL             "XDongle"
#define EEBUS_SN                "SN12345678"
#define EEBUS_PORT              4815


typedef struct {
    char pubkey[256];
    char privkey[256];
    char crt[1024];
    char ski[41];
} eebus_key_t;

// value scaled by 10^(-2), e.g 99000 to power_total will result in setting 990.00W
typedef struct {
    int32_t power_total;
    int32_t power_phase_a;
    int32_t power_phase_b;
    int32_t power_phase_c;

    int32_t energy_produced;
    int32_t energy_consumed;

    int32_t current_phase_a;
    int32_t current_phase_b;
    int32_t current_phase_c;

    int32_t voltage_phase_a;
    int32_t voltage_phase_b;
    int32_t voltage_phase_c;
    int32_t voltage_phase_ab;
    int32_t voltage_phase_bc;
    int32_t voltage_phase_ac;

    int32_t frequency;
} eebus_mpc_measurement_data_t;

void eebus_task_cb(void *pvParameters);
EebusError eebus_set_mpc_measurement(eebus_mpc_measurement_data_t ms_data);

#endif  /* EEBUS_PROCESS_H_ */
