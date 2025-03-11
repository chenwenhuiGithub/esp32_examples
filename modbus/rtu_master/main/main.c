#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#define CONFIG_MODBUS_UART_PORT             UART_NUM_2
#define CONFIG_MODBUS_UART_PIN_RX           16
#define CONFIG_MODBUS_UART_PIN_TX           17
#define CONFIG_MODBUS_UART_BAUD             115200
#define CONFIG_MODBUS_SLAVE_UID             1

#define MODBUS_CMD_READ_COIL                0x01
#define MODBUS_CMD_READ_DISCRETE            0x02
#define MODBUS_CMD_READ_HOLDING             0x03
#define MODBUS_CMD_READ_INPUT               0x04
#define MODBUS_CMD_WRITE_SINGLE_COIL        0x05
#define MODBUS_CMD_WRITE_SINGLE_HOLDING     0x06
#define MODBUS_CMD_WRITE_MULTIPLE_COIL      0x0f
#define MODBUS_CMD_WRITE_MULTIPLE_HOLDING   0x10


static const char *TAG = "rtu_master";

static uint16_t calc_crc16(uint8_t *data, uint16_t length) {
    uint16_t crc = 0xFFFF;
    uint16_t i = 0, j = 0;

    for (i = 0; i < length; i++) {
        crc ^= data[i];
        for (j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

static uint8_t check_crc16(uint8_t *data, uint16_t len) {
    uint16_t crc_calc = 0, crc_recv = 0;

    crc_calc = calc_crc16(data, len - 2);
    crc_recv = (data[len - 1] << 8) | data[len -2];
    if (crc_calc != crc_recv) {
        return 1;
    }
    return 0;
}

static void read_coil(uint16_t start_addr, uint16_t quantity, uint8_t *value) {
    uint8_t req[8] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t crc = 0, i = 0, i_src_byte = 0, i_src_bit = 0, i_des_byte = 0, i_des_bit = 0;

    req[0] = CONFIG_MODBUS_SLAVE_UID;
    req[1] = MODBUS_CMD_READ_COIL;
    req[2] = start_addr >> 8;
    req[3] = start_addr;
    req[4] = quantity >> 8;
    req[5] = quantity;
    crc = calc_crc16(req, 6);
    req[6] = crc;
    req[7] = crc >> 8;
    req_len = 8;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);

    resp_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, resp, sizeof(resp), pdMS_TO_TICKS(100)); // block until timeout or resp full
    if (resp_len <= 0) {
        ESP_LOGW(TAG, "recv timeout");
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (check_crc16(resp, resp_len)) {
            ESP_LOGE(TAG, "crc not matched");
        } else {
            if (resp[1] & 0x80) {
                ESP_LOGE(TAG, "error:0x%02x", resp[2]);
            } else {
                for (i = 0; i < quantity; i++) {
                    i_src_byte = 3 + (i / 8);
                    i_src_bit = i % 8;
                    i_des_byte = i / 8;
                    i_des_bit = i % 8;
                    if (resp[i_src_byte] & (1 << i_src_bit)) {
                        value[i_des_byte] |= (1 << i_des_bit);
                    }
                }
            }
        }
    }
}

static void read_discrete(uint16_t start_addr, uint16_t quantity, uint8_t *value) {
    uint8_t req[8] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t crc = 0, i = 0, i_src_byte = 0, i_src_bit = 0, i_des_byte = 0, i_des_bit = 0;

    req[0] = CONFIG_MODBUS_SLAVE_UID;
    req[1] = MODBUS_CMD_READ_DISCRETE;
    req[2] = start_addr >> 8;
    req[3] = start_addr;
    req[4] = quantity >> 8;
    req[5] = quantity;
    crc = calc_crc16(req, 6);
    req[6] = crc;
    req[7] = crc >> 8;
    req_len = 8;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);

    resp_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, resp, sizeof(resp), pdMS_TO_TICKS(100));
    if (resp_len <= 0) {
        ESP_LOGW(TAG, "recv timeout");
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (check_crc16(resp, resp_len)) {
            ESP_LOGE(TAG, "crc not matched");
        } else {
            if (resp[1] & 0x80) {
                ESP_LOGE(TAG, "error:0x%02x", resp[2]);
            } else {
                for (i = 0; i < quantity; i++) {
                    i_src_byte = 3 + (i / 8);
                    i_src_bit = i % 8;
                    i_des_byte = i / 8;
                    i_des_bit = i % 8;
                    if (resp[i_src_byte] & (1 << i_src_bit)) {
                        value[i_des_byte] |= (1 << i_des_bit);
                    }
                }
            }
        }
    }
}

static void read_holding(uint16_t start_addr, uint16_t quantity, uint16_t *value) {
    uint8_t req[8] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t crc = 0, i = 0;

    req[0] = CONFIG_MODBUS_SLAVE_UID;
    req[1] = MODBUS_CMD_READ_HOLDING;
    req[2] = start_addr >> 8;
    req[3] = start_addr;
    req[4] = quantity >> 8;
    req[5] = quantity;
    crc = calc_crc16(req, 6);
    req[6] = crc;
    req[7] = crc >> 8;
    req_len = 8;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);

    resp_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, resp, sizeof(resp), pdMS_TO_TICKS(100));
    if (resp_len <= 0) {
        ESP_LOGW(TAG, "recv timeout");
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (check_crc16(resp, resp_len)) {
            ESP_LOGE(TAG, "crc not matched");
        } else {
            if (resp[1] & 0x80) {
                ESP_LOGE(TAG, "error:0x%02x", resp[2]);
            } else {
                for (i = 0; i < quantity; i++) {
                    value[i] = (resp[2 * i + 3] << 8) | resp[2 * i + 4];
                }
            }
        }
    }
}

static void read_input(uint16_t start_addr, uint16_t quantity, uint16_t *value) {
    uint8_t req[8] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t crc = 0, i = 0;

    req[0] = CONFIG_MODBUS_SLAVE_UID;
    req[1] = MODBUS_CMD_READ_INPUT;
    req[2] = start_addr >> 8;
    req[3] = start_addr;
    req[4] = quantity >> 8;
    req[5] = quantity;
    crc = calc_crc16(req, 6);
    req[6] = crc;
    req[7] = crc >> 8;
    req_len = 8;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);

    resp_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, resp, sizeof(resp), pdMS_TO_TICKS(100));
    if (resp_len <= 0) {
        ESP_LOGW(TAG, "recv timeout");
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (check_crc16(resp, resp_len)) {
            ESP_LOGE(TAG, "crc not matched");
        } else {
            if (resp[1] & 0x80) {
                ESP_LOGE(TAG, "error:0x%02x", resp[2]);
            } else {
                for (i = 0; i < quantity; i++) {
                    value[i] = (resp[2 * i + 3] << 8) | resp[2 * i + 4];
                }
            }
        }
    }
}

static void write_single_coil(uint16_t start_addr, uint8_t value) {
    uint8_t req[8] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t crc = 0;

    req[0] = CONFIG_MODBUS_SLAVE_UID;
    req[1] = MODBUS_CMD_WRITE_SINGLE_COIL;
    req[2] = start_addr >> 8;
    req[3] = start_addr;
    if (value) {
        req[4] = 0xff;
        req[5] = 0x00; // value, 0xff00 - 1, 0x0000 - 0
    } else {
        req[4] = 0x00;
        req[5] = 0x00;
    }
    crc = calc_crc16(req, 6);
    req[6] = crc;
    req[7] = crc >> 8;
    req_len = 8;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);

    resp_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, resp, sizeof(resp), pdMS_TO_TICKS(100));
    if (resp_len <= 0) {
        ESP_LOGW(TAG, "recv timeout");
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (check_crc16(resp, resp_len)) {
            ESP_LOGE(TAG, "crc not matched");
        } else {
            if (resp[1] & 0x80) {
                ESP_LOGE(TAG, "error:0x%02x", resp[2]);
            }
        }
    }
}

static void write_single_holding(uint16_t start_addr, uint16_t value) {
    uint8_t req[8] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t crc = 0;

    req[0] = CONFIG_MODBUS_SLAVE_UID;
    req[1] = MODBUS_CMD_WRITE_SINGLE_HOLDING;
    req[2] = start_addr >> 8;
    req[3] = start_addr;
    req[4] = value >> 8;
    req[5] = value;
    crc = calc_crc16(req, 6);
    req[6] = crc;
    req[7] = crc >> 8;
    req_len = 8;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);

    resp_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, resp, sizeof(resp), pdMS_TO_TICKS(100));
    if (resp_len <= 0) {
        ESP_LOGW(TAG, "recv timeout");
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (check_crc16(resp, resp_len)) {
            ESP_LOGE(TAG, "crc not matched");
        } else {
            if (resp[1] & 0x80) {
                ESP_LOGE(TAG, "error:0x%02x", resp[2]);
            }
        }
    }
}

static void write_multiple_coil(uint16_t start_addr, uint16_t quantity, uint8_t *value) {
    uint8_t req[128] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t crc = 0, i = 0;
    uint8_t value_byte = 0;

    value_byte = (quantity / 8) + (quantity % 8 ? 1 : 0);
    req[0] = CONFIG_MODBUS_SLAVE_UID;
    req[1] = MODBUS_CMD_WRITE_MULTIPLE_COIL;
    req[2] = start_addr >> 8;
    req[3] = start_addr;
    req[4] = quantity >> 8;
    req[5] = quantity;
    req[6] = value_byte;
    for (i = 0; i < value_byte; i++) {
        req[7 + i] = value[i];
    }
    crc = calc_crc16(req, 7 + value_byte);
    req[7 + value_byte] = crc;
    req[8 + value_byte] = crc >> 8;
    req_len = 9 + value_byte;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);

    resp_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, resp, sizeof(resp), pdMS_TO_TICKS(100));
    if (resp_len <= 0) {
        ESP_LOGW(TAG, "recv timeout");
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (check_crc16(resp, resp_len)) {
            ESP_LOGE(TAG, "crc not matched");
        } else {
            if (resp[1] & 0x80) {
                ESP_LOGE(TAG, "error:0x%02x", resp[2]);
            }
        }
    }
}

static void write_multiple_holding(uint16_t start_addr, uint16_t quantity, uint16_t *value) {
    uint8_t req[128] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t crc = 0, i = 0;
    uint8_t value_byte = 0;

    value_byte = quantity * sizeof(uint16_t);
    req[0] = CONFIG_MODBUS_SLAVE_UID;
    req[1] = MODBUS_CMD_WRITE_MULTIPLE_HOLDING;
    req[2] = start_addr >> 8;
    req[3] = start_addr;
    req[4] = quantity >> 8;
    req[5] = quantity;
    req[6] = value_byte;
    for (i = 0; i < quantity; i++) {
        req[7 + i * 2] = value[i] >> 8;
        req[8 + i * 2] = value[i];
    }
    crc = calc_crc16(req, 7 + value_byte);
    req[7 + value_byte] = crc;
    req[8 + value_byte] = crc >> 8;
    req_len = 9 + value_byte;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);

    resp_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, resp, sizeof(resp), pdMS_TO_TICKS(100));
    if (resp_len <= 0) {
        ESP_LOGW(TAG, "recv timeout");
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (check_crc16(resp, resp_len)) {
            ESP_LOGE(TAG, "crc not matched");
        } else {
            if (resp[1] & 0x80) {
                ESP_LOGE(TAG, "error:0x%02x", resp[2]);
            }
        }
    }
}

static void rtu_master_cb() {
    uart_config_t uart_cfg = {
        .baud_rate = CONFIG_MODBUS_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uint8_t r_coil[3] = {0};
    uint8_t r_discrete[2] = {0};
    uint16_t r_input[3] = {0};
    uint16_t r_holding[5] = {0};
    uint8_t w_coil_single = 0x00;
    uint8_t w_coil_mult[2] = {0xbd, 0x03};
    uint16_t w_holding_single = 0x3345;
    uint16_t w_holding_mult[3] = {0x5567, 0x7789, 0x9901};

    uart_driver_install(CONFIG_MODBUS_UART_PORT, 1024, 0, 0, NULL, 0);
    uart_param_config(CONFIG_MODBUS_UART_PORT, &uart_cfg);
    uart_set_pin(CONFIG_MODBUS_UART_PORT, CONFIG_MODBUS_UART_PIN_TX, CONFIG_MODBUS_UART_PIN_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);


    ESP_LOGI(TAG, "read discrete bit_0");
    memset(r_discrete, 0, sizeof(r_discrete));
    read_discrete(0, 1, r_discrete);
    ESP_LOGI(TAG, "%u", r_discrete[0] & 0x01);
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "read discrete bit_9..1");
    memset(r_discrete, 0, sizeof(r_discrete));
    read_discrete(1, 9, r_discrete);
    ESP_LOGI(TAG, "[9][8 7 6 5 4 3 2 1]");
    ESP_LOGI(TAG, "[%u][%u %u %u %u %u %u %u %u]",
        r_discrete[1] & 0x01,
        (r_discrete[0] & 0x80) ? 1 : 0,
        (r_discrete[0] & 0x40) ? 1 : 0,
        (r_discrete[0] & 0x20) ? 1 : 0,
        (r_discrete[0] & 0x10) ? 1 : 0,
        (r_discrete[0] & 0x08) ? 1 : 0,
        (r_discrete[0] & 0x04) ? 1 : 0,
        (r_discrete[0] & 0x02) ? 1 : 0,
        r_discrete[0] & 0x01);
    vTaskDelay(pdMS_TO_TICKS(300));


    ESP_LOGI(TAG, "read coil bit_1");
    memset(r_coil, 0, sizeof(r_coil));
    read_coil(1, 1, r_coil);
    ESP_LOGI(TAG, "%u", r_coil[0] & 0x01);
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "read coil bit_14..5");
    memset(r_coil, 0, sizeof(r_coil));
    read_coil(5, 10, r_coil);
    ESP_LOGI(TAG, "[14 13][12 11 10 9 8 7 6 5]");
    ESP_LOGI(TAG, "[ %u  %u][ %u  %u  %u %u %u %u %u %u]",
        (r_coil[1] & 0x02) ? 1 : 0,
        r_coil[1] & 0x01,
        (r_coil[0] & 0x80) ? 1 : 0,
        (r_coil[0] & 0x40) ? 1 : 0,
        (r_coil[0] & 0x20) ? 1 : 0,
        (r_coil[0] & 0x10) ? 1 : 0,
        (r_coil[0] & 0x08) ? 1 : 0,
        (r_coil[0] & 0x04) ? 1 : 0,
        (r_coil[0] & 0x02) ? 1 : 0,
        r_coil[0] & 0x01);
    vTaskDelay(pdMS_TO_TICKS(300));


    ESP_LOGI(TAG, "write coil bit_1");
    write_single_coil(1, w_coil_single);
    ESP_LOGI(TAG, "%u", w_coil_single);
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "write coil bit_14..5");
    write_multiple_coil(5, 10, w_coil_mult);
    ESP_LOGI(TAG, "[14 13][12 11 10 9 8 7 6 5]");
    ESP_LOGI(TAG, "[ %u  %u][ %u  %u  %u %u %u %u %u %u]",
        (w_coil_mult[1] & 0x02) ? 1 : 0,
        w_coil_mult[1] & 0x01,
        (w_coil_mult[0] & 0x80) ? 1 : 0,
        (w_coil_mult[0] & 0x40) ? 1 : 0,
        (w_coil_mult[0] & 0x20) ? 1 : 0,
        (w_coil_mult[0] & 0x10) ? 1 : 0,
        (w_coil_mult[0] & 0x08) ? 1 : 0,
        (w_coil_mult[0] & 0x04) ? 1 : 0,
        (w_coil_mult[0] & 0x02) ? 1 : 0,
        w_coil_mult[0] & 0x01);
    vTaskDelay(pdMS_TO_TICKS(300));


    ESP_LOGI(TAG, "read coil bit_1");
    memset(r_coil, 0, sizeof(r_coil));
    read_coil(1, 1, r_coil);
    ESP_LOGI(TAG, "%u", r_coil[0] & 0x01);
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "read coil bit_14..5");
    memset(r_coil, 0, sizeof(r_coil));
    read_coil(5, 10, r_coil);
    ESP_LOGI(TAG, "[14 13][12 11 10 9 8 7 6 5]");
    ESP_LOGI(TAG, "[ %u  %u][ %u  %u  %u %u %u %u %u %u]",
        (r_coil[1] & 0x02) ? 1 : 0,
        r_coil[1] & 0x01,
        (r_coil[0] & 0x80) ? 1 : 0,
        (r_coil[0] & 0x40) ? 1 : 0,
        (r_coil[0] & 0x20) ? 1 : 0,
        (r_coil[0] & 0x10) ? 1 : 0,
        (r_coil[0] & 0x08) ? 1 : 0,
        (r_coil[0] & 0x04) ? 1 : 0,
        (r_coil[0] & 0x02) ? 1 : 0,
        r_coil[0] & 0x01);
    vTaskDelay(pdMS_TO_TICKS(300));


    ESP_LOGI(TAG, "read input reg_0");
    memset(r_input, 0, sizeof(r_input));
    read_input(0, 1, r_input);
    ESP_LOGI(TAG, "0x%04x", r_input[0]);
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "read input reg_2..1");
    memset(r_input, 0, sizeof(r_input));
    read_input(1, 2, r_input);
    ESP_LOGI(TAG, "[2]:0x%04x [1]:0x%04x", r_input[1], r_input[0]);
    vTaskDelay(pdMS_TO_TICKS(1000));


    ESP_LOGI(TAG, "read holding reg_1");
    memset(r_holding, 0, sizeof(r_holding));
    read_holding(1, 1, r_holding);
    ESP_LOGI(TAG, "0x%04x", r_holding[0]);
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "read holding reg_4..2");
    memset(r_holding, 0, sizeof(r_holding));
    read_holding(2, 3, r_holding);
    ESP_LOGI(TAG, "[4]:0x%04x [3]:0x%04x [2]:0x%04x", r_holding[2], r_holding[1], r_holding[0]);
    vTaskDelay(pdMS_TO_TICKS(300));


    ESP_LOGI(TAG, "write holding reg_1");
    write_single_holding(1, w_holding_single);
    ESP_LOGI(TAG, "0x%04x", w_holding_single);
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "write holding reg_4..2");
    write_multiple_holding(2, 3, w_holding_mult);
    ESP_LOGI(TAG, "[4]:0x%04x [3]:0x%04x [2]:0x%04x", w_holding_mult[2], w_holding_mult[1], w_holding_mult[0]);
    vTaskDelay(pdMS_TO_TICKS(300));


    ESP_LOGI(TAG, "read holding reg_1");
    memset(r_holding, 0, sizeof(r_holding));
    read_holding(1, 1, r_holding);
    ESP_LOGI(TAG, "0x%04x", r_holding[0]);
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "read holding reg_4..2");
    memset(r_holding, 0, sizeof(r_holding));
    read_holding(2, 3, r_holding);
    ESP_LOGI(TAG, "[4]:0x%04x [3]:0x%04x [2]:0x%04x", r_holding[2], r_holding[1], r_holding[0]);
    vTaskDelay(pdMS_TO_TICKS(300));

    vTaskDelete(NULL);
}

void app_main(void)
{
    esp_err_t err = ESP_OK;
    
    err = nvs_flash_init();
    if (ESP_ERR_NVS_NO_FREE_PAGES == err || ESP_ERR_NVS_NEW_VERSION_FOUND == err) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "nvs_flash_init error:%d", err);
        return;
    }

    xTaskCreate(rtu_master_cb, "rtu_master", 4096, NULL, 5, NULL);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
