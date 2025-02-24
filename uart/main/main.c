#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"

#define CONFIG_UART_PORT                        UART_NUM_2
#define CONFIG_UART_PIN_RX                      16
#define CONFIG_UART_PIN_TX                      17
#define CONFIG_UART_BAUD                        115200


static uint8_t rx_data[256] = {0};

void app_main(void) {
    int rx_len = 0;
    uart_config_t uart_cfg = {
        .baud_rate = CONFIG_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    uart_driver_install(CONFIG_UART_PORT, 1024, 0, 0, NULL, 0);
    uart_param_config(CONFIG_UART_PORT, &uart_cfg);
    // UART0(RX:3, TX:1), UART2(RX:16, TX:17)
    uart_set_pin(CONFIG_UART_PORT, CONFIG_UART_PIN_TX, CONFIG_UART_PIN_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    while (1) {
        rx_len = uart_read_bytes(CONFIG_UART_PORT, rx_data, sizeof(rx_data), pdMS_TO_TICKS(100)); // keep block until timeout or buf full
        if (rx_len > 0) {
            uart_write_bytes(CONFIG_UART_PORT, rx_data, rx_len);
        }
    }
}
