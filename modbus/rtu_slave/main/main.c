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
#define CONFIG_MODBUS_DISCRETE_NUM          10
#define CONFIG_MODBUS_COIL_NUM              20
#define CONFIG_MODBUS_INPUT_NUM             3
#define CONFIG_MODBUS_HOLDING_NUM           5

#define MODBUS_CMD_READ_COIL                0x01
#define MODBUS_CMD_READ_DISCRETE            0x02
#define MODBUS_CMD_READ_HOLDING             0x03
#define MODBUS_CMD_READ_INPUT               0x04
#define MODBUS_CMD_WRITE_SINGLE_COIL        0x05
#define MODBUS_CMD_WRITE_SINGLE_HOLDING     0x06
#define MODBUS_CMD_WRITE_MULTIPLE_COIL      0x0f
#define MODBUS_CMD_WRITE_MULTIPLE_HOLDING   0x10

#define MODBUS_ERR_ILLEGAL_FUNC             0x01
#define MODBUS_ERR_ILLEGAL_DATA_ADDR        0x02
#define MODBUS_ERR_ILLEGAL_DATA_VALUE       0x03
#define MODBUS_ERR_SLAVE_FAILURE            0x04


static const char *TAG = "rtu_slave";
static uint8_t discrete[(CONFIG_MODBUS_DISCRETE_NUM / 8) + (CONFIG_MODBUS_DISCRETE_NUM % 8 ? 1 : 0)] = {0};
static uint8_t coil[(CONFIG_MODBUS_COIL_NUM / 8) + (CONFIG_MODBUS_COIL_NUM % 8 ? 1 : 0)] = {0};
static uint16_t input[CONFIG_MODBUS_INPUT_NUM] = {0};
static uint16_t holding[CONFIG_MODBUS_HOLDING_NUM] = {0};


static void init_slave_data() {
    discrete[0] |= 0x11;
    discrete[1] |= 0x02; // bit 0,4,9

    coil[0] |= 0x42;
    coil[1] |= 0x08;
    coil[2] |= 0x01;     // bit 1,6,11,16

    input[0] = 0x1234;
    input[1] = 0x5678;
    input[2] = 0xabcd;

    holding[0] = 0x0011;
    holding[1] = 0x2233;
    holding[2] = 0x4455;
    holding[3] = 0x6677;
    holding[4] = 0x8899;
}

static uint16_t calc_crc16(uint8_t *data, uint16_t len) {
    uint16_t crc = 0xFFFF;
    uint16_t i = 0, j = 0;

    for (i = 0; i < len; i++) {
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

static void response_err(uint8_t err, uint8_t *req, uint32_t req_len) {
    uint8_t resp[5] = {0};
    uint32_t resp_len = 0;
    uint16_t crc = 0;

    resp[0] = req[0]; // uid
    resp[1] = req[1] | 0x80; // cmd
    resp[2] = err; // data: err code
    crc = calc_crc16(resp, 3);
    resp[3] = crc;
    resp[4] = crc >> 8;
    resp_len = 5;
    ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, resp, resp_len);
}

static void process_read_coil(uint8_t *req, uint32_t req_len) {
    uint16_t start_addr = 0, quantity = 0;
    uint8_t resp[128] = {0};
    uint32_t resp_len = 0;
    uint16_t i = 0, i_src_byte = 0, i_src_bit = 0, i_des_byte = 0, i_des_bit = 0;
    uint16_t crc = 0;
    uint8_t value_byte = 0;

    start_addr = (req[2] << 8) | req[3];
    quantity = (req[4] << 8) | req[5];
    ESP_LOGI(TAG, "read coil, start_addr:0x%04x quantity:%u", start_addr, quantity);
    if ((start_addr >= CONFIG_MODBUS_COIL_NUM) || (quantity > CONFIG_MODBUS_COIL_NUM)) {
        ESP_LOGE(TAG, "invalid para, coil size:%u", CONFIG_MODBUS_COIL_NUM);
        response_err(MODBUS_ERR_ILLEGAL_DATA_ADDR, req, req_len);
        return;
    }

    for (i = 0; i < quantity; i++) {
        i_src_byte = (start_addr + i) / 8;
        i_src_bit = (start_addr + i) % 8;
        i_des_byte = i / 8;
        i_des_bit = i % 8;
        if (coil[i_src_byte] & (1 << i_src_bit)) {
            resp[i_des_byte + 3] |= (1 << i_des_bit); // data: coil value
        }
    }

    value_byte = (quantity / 8) + (quantity % 8 ? 1 : 0);
    resp[0] = req[0]; // uid
    resp[1] = req[1]; // cmd
    resp[2] = value_byte; // data: coil byte cnt
    crc = calc_crc16(resp, value_byte + 3);
    resp[value_byte + 3] = crc;
    resp[value_byte + 4] = crc >> 8;
    resp_len = value_byte + 5;
    ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, resp, resp_len);
}

static void process_read_discrete(uint8_t *req, uint32_t req_len) {
    uint16_t start_addr = 0, quantity = 0;
    uint8_t resp[128] = {0};
    uint32_t resp_len = 0;
    uint16_t i = 0, i_src_byte = 0, i_src_bit = 0, i_des_byte = 0, i_des_bit = 0;
    uint16_t crc = 0;
    uint8_t value_byte = 0;

    start_addr = (req[2] << 8) | req[3];
    quantity = (req[4] << 8) | req[5];
    ESP_LOGI(TAG, "read discrete, start_addr:0x%04x quantity:%u", start_addr, quantity);
    if ((start_addr >= CONFIG_MODBUS_DISCRETE_NUM) || (quantity > CONFIG_MODBUS_DISCRETE_NUM)) {
        ESP_LOGE(TAG, "invalid para, discrete size:%u", CONFIG_MODBUS_DISCRETE_NUM);
        response_err(MODBUS_ERR_ILLEGAL_DATA_ADDR, req, req_len);
        return;
    }

    for (i = 0; i < quantity; i++) {
        i_src_byte = (start_addr + i) / 8;
        i_src_bit = (start_addr + i) % 8;
        i_des_byte = i / 8;
        i_des_bit = i % 8;
        if (discrete[i_src_byte] & (1 << i_src_bit)) {
            resp[i_des_byte + 3] |= (1 << i_des_bit); // data: discrete value
        }
    }

    value_byte = (quantity / 8) + (quantity % 8 ? 1 : 0);
    resp[0] = req[0]; // uid
    resp[1] = req[1]; // cmd
    resp[2] = value_byte; // data: discrete byte cnt
    crc = calc_crc16(resp, value_byte + 3);
    resp[value_byte + 3] = crc;
    resp[value_byte + 4] = crc >> 8;
    resp_len = value_byte + 5;
    ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, resp, resp_len);
}

static void process_read_holding(uint8_t *req, uint32_t req_len) {
    uint16_t start_addr = 0, quantity = 0;
    uint8_t resp[128] = {0};
    uint32_t resp_len = 0;
    uint16_t i = 0;
    uint16_t crc = 0;
    uint8_t value_byte = 0;

    start_addr = (req[2] << 8) | req[3];
    quantity = (req[4] << 8) | req[5];
    ESP_LOGI(TAG, "read holding, start_addr:0x%04x quantity:%u", start_addr, quantity);
    if ((start_addr >= CONFIG_MODBUS_HOLDING_NUM) || (quantity > CONFIG_MODBUS_HOLDING_NUM)) {
        ESP_LOGE(TAG, "invalid para, holding size:%u", CONFIG_MODBUS_HOLDING_NUM);
        response_err(MODBUS_ERR_ILLEGAL_DATA_ADDR, req, req_len);
        return;
    }

    for (i = 0; i < quantity; i++) {
        resp[i * 2 + 3] = holding[start_addr + i] >> 8;
        resp[i * 2 + 4] = holding[start_addr + i]; // data: holding value
    }

    value_byte = quantity * 2;
    resp[0] = req[0]; // uid
    resp[1] = req[1]; // cmd
    resp[2] = value_byte; // data: holding byte cnt
    crc = calc_crc16(resp, value_byte + 3);
    resp[value_byte + 3] = crc;
    resp[value_byte + 4] = crc >> 8;
    resp_len = value_byte + 5;
    ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, resp, resp_len);
}

static void process_read_input(uint8_t *req, uint32_t req_len) {
    uint16_t start_addr = 0, quantity = 0;
    uint8_t resp[128] = {0};
    uint32_t resp_len = 0;
    uint16_t i = 0;
    uint16_t crc = 0;
    uint8_t value_byte = 0;

    start_addr = (req[2] << 8) | req[3];
    quantity = (req[4] << 8) | req[5];
    ESP_LOGI(TAG, "read input, start_addr:0x%04x quantity:%u", start_addr, quantity);
    if ((start_addr >= CONFIG_MODBUS_INPUT_NUM) || (quantity > CONFIG_MODBUS_INPUT_NUM)) {
        ESP_LOGE(TAG, "invalid para, input size:%u", CONFIG_MODBUS_INPUT_NUM);
        response_err(MODBUS_ERR_ILLEGAL_DATA_ADDR, req, req_len);
        return;
    }

    for (i = 0; i < quantity; i++) {
        resp[i * 2 + 3] = input[start_addr + i] >> 8;
        resp[i * 2 + 4] = input[start_addr + i]; // data: input value
    }

    value_byte = quantity * 2;
    resp[0] = req[0]; // uid
    resp[1] = req[1]; // cmd
    resp[2] = value_byte; // data: input byte cnt
    crc = calc_crc16(resp, value_byte + 3);
    resp[value_byte + 3] = crc;
    resp[value_byte + 4] = crc >> 8;
    resp_len = value_byte + 5;
    ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, resp, resp_len);
}

static void process_write_single_coil(uint8_t *req, uint32_t req_len) {
    uint16_t start_addr = 0, value = 0;
    uint16_t i_byte = 0, i_bit = 0;

    start_addr = (req[2] << 8) | req[3];
    value = (req[4] << 8) | req[5];
    ESP_LOGI(TAG, "write single coil, start_addr:0x%04x value:0x%04x", start_addr, value);
    if (start_addr >= CONFIG_MODBUS_COIL_NUM) {
        ESP_LOGE(TAG, "invalid para, coil size:%u", CONFIG_MODBUS_COIL_NUM);
        response_err(MODBUS_ERR_ILLEGAL_DATA_ADDR, req, req_len);
        return;
    }

    i_byte = start_addr / 8;
    i_bit = start_addr % 8;
    if (0xff00 == value) {
        coil[i_byte] |= (1 << i_bit);
    } else if (0x0000 == value) {
        coil[i_byte] &= ~(1 << i_bit);
    } else {
        ESP_LOGE(TAG, "unknown value");
        response_err(MODBUS_ERR_ILLEGAL_DATA_VALUE, req, req_len);
        return;
    }
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);
}

static void process_write_single_holding(uint8_t *req, uint32_t req_len) {
    uint16_t start_addr = 0, value = 0;

    start_addr = (req[2] << 8) | req[3];
    value = (req[4] << 8) | req[5];
    ESP_LOGI(TAG, "write single holding, start_addr:0x%04x value:0x%04x", start_addr, value);
    if (start_addr >= CONFIG_MODBUS_HOLDING_NUM) {
        ESP_LOGE(TAG, "invalid para, holding size:%u", CONFIG_MODBUS_HOLDING_NUM);
        response_err(MODBUS_ERR_ILLEGAL_DATA_ADDR, req, req_len);
        return;
    }

    holding[start_addr] = value;

    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, req, req_len);
}

static void process_write_multiple_coil(uint8_t *req, uint32_t req_len) {
    uint16_t start_addr = 0, quantity = 0;
    uint8_t resp[8] = {0};
    uint32_t resp_len = 0;
    uint16_t i = 0, i_src_byte = 0, i_src_bit = 0, i_des_byte = 0, i_des_bit = 0;
    uint16_t crc = 0;

    start_addr = (req[2] << 8) | req[3];
    quantity = (req[4] << 8) | req[5];
    ESP_LOGI(TAG, "write multiple coil, start_addr:0x%04x quantity:%u", start_addr, quantity);
    if ((start_addr >= CONFIG_MODBUS_COIL_NUM) || (quantity > CONFIG_MODBUS_COIL_NUM)) {
        ESP_LOGE(TAG, "invalid para, coil size:%u", CONFIG_MODBUS_COIL_NUM);
        response_err(MODBUS_ERR_ILLEGAL_DATA_ADDR, req, req_len);
        return;
    }

    for (i = 0; i < quantity; i++) {
        i_src_byte = i / 8;
        i_src_bit = i % 8;
        i_des_byte = (start_addr + i) / 8;
        i_des_bit = (start_addr + i) % 8;
        if (req[i_src_byte + 7] & (1 << i_src_bit)) {
            coil[i_des_byte] |= (1 << i_des_bit);
        } else {
            coil[i_des_byte] &= ~(1 << i_des_bit);
        }
    }

    resp[0] = req[0]; // uid
    resp[1] = req[1]; // cmd
    resp[2] = req[2];
    resp[3] = req[3]; // start_addr
    resp[4] = req[4];
    resp[5] = req[5]; // quantity
    crc = calc_crc16(req, 6);
    resp[6] = crc;
    resp[7] = crc >> 8;
    resp_len = 8;
    ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, resp, resp_len);
}

static void process_write_multiple_holding(uint8_t *req, uint32_t req_len) {
    uint16_t start_addr = 0, quantity = 0;
    uint8_t resp[8] = {0};
    uint32_t resp_len = 0;
    uint16_t i = 0;
    uint16_t crc = 0;

    start_addr = (req[2] << 8) | req[3];
    quantity = (req[4] << 8) | req[5];
    ESP_LOGI(TAG, "write multiple holding, start_addr:0x%04x quantity:%u", start_addr, quantity);
    if ((start_addr >= CONFIG_MODBUS_HOLDING_NUM) || (quantity > CONFIG_MODBUS_HOLDING_NUM)) {
        ESP_LOGE(TAG, "invalid para, holding size:%u", CONFIG_MODBUS_HOLDING_NUM);
        response_err(MODBUS_ERR_ILLEGAL_DATA_ADDR, req, req_len);
        return;
    }

    for (i = 0; i < quantity; i++) {
        holding[start_addr + i] = (uint16_t)(req[i * 2 + 7] << 8) | req[i * 2 + 8];
    }

    resp[0] = req[0]; // uid
    resp[1] = req[1]; // cmd
    resp[2] = req[2];
    resp[3] = req[3]; // start_addr
    resp[4] = req[4];
    resp[5] = req[5]; // quantity
    crc = calc_crc16(req, 6);
    resp[6] = crc;
    resp[7] = crc >> 8;
    resp_len = 8;
    ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
    uart_write_bytes(CONFIG_MODBUS_UART_PORT, resp, resp_len);
}

// [0]:uid
// [1]:cmd
// [2..]:data
// [-2..-1]:crc16
static void process_cmd(uint8_t *req, uint32_t req_len) {
    uint8_t uid = 0, cmd = 0;
    uint16_t crc_calc = 0, crc_recv = 0;

    uid = req[0];
    cmd = req[1];
    crc_calc = calc_crc16(req, req_len - 2);
    crc_recv = (req[req_len - 1] << 8) | req[req_len -2];

    if (crc_calc != crc_recv) {
        ESP_LOGE(TAG, "crc not matched, calc:0x%04x recv:0x%04x", crc_calc, crc_recv);
        response_err(MODBUS_ERR_SLAVE_FAILURE, req, req_len);
        return;        
    }

    if (CONFIG_MODBUS_SLAVE_UID != uid) {
        ESP_LOGE(TAG, "uid not matched, slave:0x%02x master:0x%02x", CONFIG_MODBUS_SLAVE_UID, uid);
        response_err(MODBUS_ERR_SLAVE_FAILURE, req, req_len);
        return;
    }

    switch (cmd) {
    case MODBUS_CMD_READ_COIL:
        process_read_coil(req, req_len);
        break;
    case MODBUS_CMD_READ_DISCRETE:
        process_read_discrete(req, req_len);
        break;
    case MODBUS_CMD_READ_HOLDING:
        process_read_holding(req, req_len);
        break;
    case MODBUS_CMD_READ_INPUT:
        process_read_input(req, req_len);
        break;
    case MODBUS_CMD_WRITE_SINGLE_COIL:
        process_write_single_coil(req, req_len);
        break;
    case MODBUS_CMD_WRITE_SINGLE_HOLDING:
        process_write_single_holding(req, req_len);
        break;
    case MODBUS_CMD_WRITE_MULTIPLE_COIL:
        process_write_multiple_coil(req, req_len);
        break;
    case MODBUS_CMD_WRITE_MULTIPLE_HOLDING:
        process_write_multiple_holding(req, req_len);
        break;
    default:
        ESP_LOGW(TAG, "unknown cmd:0x%02x", cmd);
        response_err(MODBUS_ERR_ILLEGAL_FUNC, req, req_len);
        break;
    }
}

static void rtu_slave_cb(void *pvParameters) {
    uart_config_t uart_cfg = {
        .baud_rate = CONFIG_MODBUS_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    int rx_len = 0;
    uint8_t rx_data[256] = {0};

    init_slave_data();

    uart_driver_install(CONFIG_MODBUS_UART_PORT, 1024, 0, 0, NULL, 0);
    uart_param_config(CONFIG_MODBUS_UART_PORT, &uart_cfg);
    uart_set_pin(CONFIG_MODBUS_UART_PORT, CONFIG_MODBUS_UART_PIN_TX, CONFIG_MODBUS_UART_PIN_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    while (1) {
        rx_len = uart_read_bytes(CONFIG_MODBUS_UART_PORT, rx_data, sizeof(rx_data), pdMS_TO_TICKS(100)); // block until timeout or rx_data full
        if (rx_len) {
            ESP_LOG_BUFFER_HEX(TAG, rx_data, rx_len);
            process_cmd(rx_data, rx_len);
        }
    }    
}

void app_main(void) {
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

    xTaskCreate(rtu_slave_cb, "rtu_slave", 4096, NULL, 5, NULL);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
