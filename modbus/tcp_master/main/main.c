#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_MODBUS_SLAVE_IP                  "192.168.108.112"
#define CONFIG_MODBUS_TCP_PORT                  502
#define CONFIG_MODBUS_SLAVE_UID                 1
#define CONFIG_MODBUS_RECV_TIMEOUT_MS           5000

#define MODBUS_CMD_READ_COIL                    0x01
#define MODBUS_CMD_READ_DISCRETE                0x02
#define MODBUS_CMD_READ_HOLDING                 0x03
#define MODBUS_CMD_READ_INPUT                   0x04
#define MODBUS_CMD_WRITE_SINGLE_COIL            0x05
#define MODBUS_CMD_WRITE_SINGLE_HOLDING         0x06
#define MODBUS_CMD_WRITE_MULTIPLE_COIL          0x0f
#define MODBUS_CMD_WRITE_MULTIPLE_HOLDING       0x10


static const char *TAG = "tcp_master";
static int sock = 0;

static uint16_t gen_trans_id() {
    static uint16_t trans_id = 0;
    return trans_id++;
}

static void read_coil(uint16_t start_addr, uint16_t quantity, uint8_t *value) {
    uint8_t req[12] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t trans_id = 0, i = 0, i_src_byte = 0, i_src_bit = 0, i_des_byte = 0, i_des_bit = 0;

    trans_id = gen_trans_id();
    req[0] = trans_id >> 8;
    req[1] = trans_id; // transaction_id
    req[2] = 0;
    req[3] = 0; // protocol_id
    req[4] = 0; 
    req[5] = 6; // len(uid + cmd + data)
    req[6] = CONFIG_MODBUS_SLAVE_UID;
    req[7] = MODBUS_CMD_READ_COIL;
    req[8] = start_addr >> 8;
    req[9] = start_addr;
    req[10] = quantity >> 8;
    req[11] = quantity;
    req_len = 12;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    send(sock, req, req_len, 0);

    resp_len = recv(sock, resp, sizeof(resp), 0);
    if (resp_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ESP_LOGW(TAG, "socket recv timeout");
        } else {
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            close(sock);
        }
    } else if (resp_len == 0) {
        ESP_LOGE(TAG, "socket closed by peer");
        close(sock);
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (resp[7] & 0x80) {
            ESP_LOGE(TAG, "error:0x%02x", resp[8]);
        } else {
            for (i = 0; i < quantity; i++) {
                i_src_byte = 9 + (i / 8);
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

static void read_discrete(uint16_t start_addr, uint16_t quantity, uint8_t *value) {
    uint8_t req[12] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t trans_id = 0, i = 0, i_src_byte = 0, i_src_bit = 0, i_des_byte = 0, i_des_bit = 0;

    trans_id = gen_trans_id();
    req[0] = trans_id >> 8;
    req[1] = trans_id; // transaction_id
    req[2] = 0;
    req[3] = 0; // protocol_id
    req[4] = 0; 
    req[5] = 6; // len(uid + cmd + data)
    req[6] = CONFIG_MODBUS_SLAVE_UID;
    req[7] = MODBUS_CMD_READ_DISCRETE;
    req[8] = start_addr >> 8;
    req[9] = start_addr;
    req[10] = quantity >> 8;
    req[11] = quantity;
    req_len = 12;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    send(sock, req, req_len, 0);

    resp_len = recv(sock, resp, sizeof(resp), 0);
    if (resp_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ESP_LOGW(TAG, "socket recv timeout");
        } else {
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            close(sock);
        }
    } else if (resp_len == 0) {
        ESP_LOGE(TAG, "socket closed by peer");
        close(sock);
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (resp[7] & 0x80) {
            ESP_LOGE(TAG, "error:0x%02x", resp[8]);
        } else {
            for (i = 0; i < quantity; i++) {
                i_src_byte = 9 + (i / 8);
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

static void read_holding(uint16_t start_addr, uint16_t quantity, uint16_t *value) {
    uint8_t req[12] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t trans_id = 0, i = 0;

    trans_id = gen_trans_id();
    req[0] = trans_id >> 8;
    req[1] = trans_id; // transaction_id
    req[2] = 0;
    req[3] = 0; // protocol_id
    req[4] = 0; 
    req[5] = 6; // len(uid + cmd + data)
    req[6] = CONFIG_MODBUS_SLAVE_UID;
    req[7] = MODBUS_CMD_READ_HOLDING;
    req[8] = start_addr >> 8;
    req[9] = start_addr;
    req[10] = quantity >> 8;
    req[11] = quantity;
    req_len = 12;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    send(sock, req, req_len, 0);

    resp_len = recv(sock, resp, sizeof(resp), 0);
    if (resp_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ESP_LOGW(TAG, "socket recv timeout");
        } else {
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            close(sock);
        }
    } else if (resp_len == 0) {
        ESP_LOGE(TAG, "socket closed by peer");
        close(sock);
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (resp[7] & 0x80) {
            ESP_LOGE(TAG, "error:0x%02x", resp[8]);
        } else {
            for (i = 0; i < quantity; i++) {
                value[i] = (resp[2 * i + 9] << 8) | resp[2 * i + 10];
            }
        }
    }
}

static void read_input(uint16_t start_addr, uint16_t quantity, uint16_t *value) {
    uint8_t req[12] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t trans_id = 0, i = 0;

    trans_id = gen_trans_id();
    req[0] = trans_id >> 8;
    req[1] = trans_id; // transaction_id
    req[2] = 0;
    req[3] = 0; // protocol_id
    req[4] = 0; 
    req[5] = 6; // len(uid + cmd + data)
    req[6] = CONFIG_MODBUS_SLAVE_UID;
    req[7] = MODBUS_CMD_READ_INPUT;
    req[8] = start_addr >> 8;
    req[9] = start_addr;
    req[10] = quantity >> 8;
    req[11] = quantity;
    req_len = 12;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    send(sock, req, req_len, 0);

    resp_len = recv(sock, resp, sizeof(resp), 0);
    if (resp_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ESP_LOGW(TAG, "socket recv timeout");
        } else {
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            close(sock);
        }
    } else if (resp_len == 0) {
        ESP_LOGE(TAG, "socket closed by peer");
        close(sock);
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (resp[7] & 0x80) {
            ESP_LOGE(TAG, "error:0x%02x", resp[8]);
        } else {
            for (i = 0; i < quantity; i++) {
                value[i] = (resp[2 * i + 9] << 8) | resp[2 * i + 10];
            }
        }
    }
}

static void write_single_coil(uint16_t start_addr, uint8_t value) {
    uint8_t req[12] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t trans_id = 0;

    trans_id = gen_trans_id();
    req[0] = trans_id >> 8;
    req[1] = trans_id; // transaction_id
    req[2] = 0;
    req[3] = 0; // protocol_id
    req[4] = 0;
    req[5] = 6; // len(uid + cmd + data)
    req[6] = CONFIG_MODBUS_SLAVE_UID;
    req[7] = MODBUS_CMD_WRITE_SINGLE_COIL;
    req[8] = start_addr >> 8;
    req[9] = start_addr;
    if (value) {
        req[10] = 0xff;
        req[11] = 0x00; // value, 0xff00 - 1, 0x0000 - 0
    } else {
        req[10] = 0x00;
        req[11] = 0x00;
    }
    req_len = 12;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    send(sock, req, req_len, 0);

    resp_len = recv(sock, resp, sizeof(resp), 0);
    if (resp_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ESP_LOGW(TAG, "socket recv timeout");
        } else {
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            close(sock);
        }
    } else if (resp_len == 0) {
        ESP_LOGE(TAG, "socket closed by peer");
        close(sock);
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (resp[7] & 0x80) {
            ESP_LOGE(TAG, "error:0x%02x", resp[8]);
        }
    }
}

static void write_single_holding(uint16_t start_addr, uint16_t value) {
    uint8_t req[12] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t trans_id = 0;

    trans_id = gen_trans_id();
    req[0] = trans_id >> 8;
    req[1] = trans_id; // transaction_id
    req[2] = 0;
    req[3] = 0; // protocol_id
    req[4] = 0; 
    req[5] = 6; // len(uid + cmd + data)
    req[6] = CONFIG_MODBUS_SLAVE_UID;
    req[7] = MODBUS_CMD_WRITE_SINGLE_HOLDING;
    req[8] = start_addr >> 8;
    req[9] = start_addr;
    req[10] = value >> 8;
    req[11] = value;
    req_len = 12;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    send(sock, req, req_len, 0);

    resp_len = recv(sock, resp, sizeof(resp), 0);
    if (resp_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ESP_LOGW(TAG, "socket recv timeout");
        } else {
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            close(sock);
        }
    } else if (resp_len == 0) {
        ESP_LOGE(TAG, "socket closed by peer");
        close(sock);
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (resp[7] & 0x80) {
            ESP_LOGE(TAG, "error:0x%02x", resp[8]);
        }
    }
}

static void write_multiple_coil(uint16_t start_addr, uint16_t quantity, uint8_t *value) {
    uint8_t req[128] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t trans_id = 0, i = 0;
    uint8_t value_byte = 0;

    value_byte = (quantity / 8) + (quantity % 8 ? 1 : 0);
    trans_id = gen_trans_id();
    req[0] = trans_id >> 8;
    req[1] = trans_id; // transaction_id
    req[2] = 0;
    req[3] = 0; // protocol_id
    req[4] = 0; 
    req[5] = 9; // len(uid + cmd + data)
    req[6] = CONFIG_MODBUS_SLAVE_UID;
    req[7] = MODBUS_CMD_WRITE_MULTIPLE_COIL;
    req[8] = start_addr >> 8;
    req[9] = start_addr;
    req[10] = quantity >> 8;
    req[11] = quantity;
    req[12] = value_byte;
    for (i = 0; i < value_byte; i++) {
        req[13 + i] = value[i];
    }
    req_len = 13 + value_byte;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    send(sock, req, req_len, 0);

    resp_len = recv(sock, resp, sizeof(resp), 0);
    if (resp_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ESP_LOGW(TAG, "socket recv timeout");
        } else {
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            close(sock);
        }
    } else if (resp_len == 0) {
        ESP_LOGE(TAG, "socket closed by peer");
        close(sock);
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (resp[7] & 0x80) {
            ESP_LOGE(TAG, "error:0x%02x", resp[8]);
        }
    }
}

static void write_multiple_holding(uint16_t start_addr, uint16_t quantity, uint16_t *value) {
    uint8_t req[128] = {0};
    uint32_t req_len = 0;
    uint8_t resp[128] = {0};
    int resp_len = 0;
    uint16_t trans_id = 0, i = 0;
    uint8_t value_byte = 0;

    value_byte = quantity * sizeof(uint16_t);
    trans_id = gen_trans_id();
    req[0] = trans_id >> 8;
    req[1] = trans_id; // transaction_id
    req[2] = 0;
    req[3] = 0; // protocol_id
    req[4] = 0; 
    req[5] = 13; // len(uid + cmd + data)
    req[6] = CONFIG_MODBUS_SLAVE_UID;
    req[7] = MODBUS_CMD_WRITE_MULTIPLE_HOLDING;
    req[8] = start_addr >> 8;
    req[9] = start_addr;
    req[10] = quantity >> 8;
    req[11] = quantity;
    req[12] = value_byte;
    for (i = 0; i < quantity; i++) {
        req[13 + i * 2] = value[i] >> 8;
        req[14 + i * 2] = value[i];
    }
    req_len = 13 + value_byte;
    ESP_LOG_BUFFER_HEX(TAG, req, req_len);
    send(sock, req, req_len, 0);

    resp_len = recv(sock, resp, sizeof(resp), 0);
    if (resp_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ESP_LOGW(TAG, "socket recv timeout");
        } else {
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            close(sock);
        }
    } else if (resp_len == 0) {
        ESP_LOGE(TAG, "socket closed by peer");
        close(sock);
    } else {
        ESP_LOG_BUFFER_HEX(TAG, resp, resp_len);
        if (resp[7] & 0x80) {
            ESP_LOGE(TAG, "error:0x%02x", resp[8]);
        }
    }
}

static void tcp_master_cb(void *pvParameters) {
    int err = 0;
    struct sockaddr_in server_addr = {0};
    struct timeval tv = {
        .tv_sec = CONFIG_MODBUS_RECV_TIMEOUT_MS / 1000,
        .tv_usec = (CONFIG_MODBUS_RECV_TIMEOUT_MS % 1000) * 1000
    };
    uint8_t r_coil[3] = {0};
    uint8_t r_discrete[2] = {0};
    uint16_t r_input[3] = {0};
    uint16_t r_holding[5] = {0};
    uint8_t w_coil_single = 0x00;
    uint8_t w_coil_mult[2] = {0xbd, 0x03};
    uint16_t w_holding_single = 0x3345;
    uint16_t w_holding_mult[3] = {0x5567, 0x7789, 0x9901};

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket create failed:%d", errno);
        goto exit;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(CONFIG_MODBUS_SLAVE_IP);
    server_addr.sin_port = htons(CONFIG_MODBUS_TCP_PORT);
    ESP_LOGI(TAG, "socket start connect, %s:%u", CONFIG_MODBUS_SLAVE_IP, CONFIG_MODBUS_TCP_PORT);
    err = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "socket connect failed:%d", errno);
        goto exit;
    }
    ESP_LOGI(TAG, "socket connect success");

    err = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (err != 0) {
        ESP_LOGE(TAG, "socket setsockopt failed:%d", errno);
        close(sock);
        goto exit;
    }


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

exit:
    vTaskDelete(NULL);
}

static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    wifi_event_sta_connected_t *evt_sta_conn = NULL;
    wifi_event_sta_disconnected_t *evt_sta_disconn = NULL;
    ip_event_got_ip_t *evt_got_ip = NULL;

    if (WIFI_EVENT == event_base) {
        switch (event_id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "WIFI_EVENT_STA_START");
            ESP_LOGI(TAG, "wifi start connect, %s:%s", CONFIG_WIFI_STA_SSID, CONFIG_WIFI_STA_PWD);
            esp_wifi_connect();
            break;
        case WIFI_EVENT_STA_CONNECTED:
            evt_sta_conn = (wifi_event_sta_connected_t *)event_data;
            ESP_LOGI(TAG, "WIFI_EVENT_STA_CONNECTED, channel:%u authmode:0x%02x aid:0x%04x bssid:"MACSTR"",
                evt_sta_conn->channel, evt_sta_conn->authmode, evt_sta_conn->aid, MAC2STR(evt_sta_conn->bssid));
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            evt_sta_disconn = (wifi_event_sta_disconnected_t *)event_data; // reason:wifi_err_reason_t
            ESP_LOGE(TAG, "WIFI_EVENT_STA_DISCONNECTED, reason:0x%02x rssi:%d", evt_sta_disconn->reason, evt_sta_disconn->rssi);
            break;
        default:
            ESP_LOGW(TAG, "unknown WIFI_EVENT:%ld", event_id);
            break;
        }
    }

    if (IP_EVENT == event_base) {
        switch (event_id) {
        case IP_EVENT_STA_GOT_IP:
            evt_got_ip = (ip_event_got_ip_t *)event_data;
            ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP, ip:"IPSTR" netmask:"IPSTR" gw:"IPSTR"",
                IP2STR(&evt_got_ip->ip_info.ip), IP2STR(&evt_got_ip->ip_info.netmask), IP2STR(&evt_got_ip->ip_info.gw));
            xTaskCreate(tcp_master_cb, "tcp_master", 4096, NULL, 5, NULL);
            break;
        case IP_EVENT_STA_LOST_IP:
            ESP_LOGE(TAG, "IP_EVENT_STA_LOST_IP");
            break;
        default:
            ESP_LOGW(TAG, "unknown IP_EVENT:%ld", event_id);
            break;
        }
    }
}

void app_main(void) {
    esp_err_t err = ESP_OK;
    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t sta_cfg = {
        .sta = {
            .ssid = CONFIG_WIFI_STA_SSID,
            .password = CONFIG_WIFI_STA_PWD,
        },
    };

    err = nvs_flash_init();
    if (ESP_ERR_NVS_NO_FREE_PAGES == err || ESP_ERR_NVS_NEW_VERSION_FOUND == err) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "nvs_flash_init error:%d", err);
        return;
    }

    esp_event_loop_create_default();
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL);

    esp_netif_init();
    esp_netif_create_default_wifi_sta();

    esp_wifi_init(&init_cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    esp_wifi_start();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
