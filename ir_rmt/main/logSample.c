#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "logSample.h"


#define CONFIG_TCP_SERVER_PORT                  8001
#define CONFIG_WS_UUIT                          "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define CONFIG_WS_RESP                          "HTTP/1.1 101 Switching Protocols\r\n" \
                                                "Connection: Upgrade\r\n" \
                                                "Upgrade: websocket\r\n" \
                                                "Sec-WebSocket-Accept: %s\r\n" \
                                                "\r\n"


static const char *TAG = "logSample";
static int client_sock = 0;
static uint8_t rx_data[1024] = {0};
static int rx_len = 0;
static uint8_t tx_data[256] = {0};
static int tx_len = 0;
static char ws_key[128] = {0};
static char ws_accept[32] = {0}; // maxsize = 20 * 4/3

static int logSample_vprintf(const char *format, va_list args) {  
    size_t len = 0;

    len = vsnprintf((char *)tx_data + 4, sizeof(tx_data) - 4, format, args);
    if (len < 126) {
        tx_data[2] = 0x81;  // Fin:1, opcode:1(Text)
        tx_data[3] = len;   // mask:0
        send(client_sock, tx_data + 2, len + 2, 0);
    } else {
        tx_data[0] = 0x81;  // Fin:1, opcode:1(Text)
        tx_data[1] = 126;   // mask:0
        tx_data[2] = len >> 8;
        tx_data[3] = len;
        send(client_sock, tx_data, len + 4, 0);
    }

    return len;
}

void calc_sha1(uint8_t *data, uint32_t data_len, uint8_t *hash) {
    const uint32_t BLOCK_SIZE = 128;
    uint32_t blocks = data_len / BLOCK_SIZE;
    uint32_t last_block_size = data_len % BLOCK_SIZE;
    uint32_t i = 0;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
    mbedtls_md_starts(&md_ctx);
    while (i < blocks) {
        mbedtls_md_update(&md_ctx, data + (i * BLOCK_SIZE), BLOCK_SIZE);
        i++;
    }
    if (last_block_size) {
        mbedtls_md_update(&md_ctx, data + (i * BLOCK_SIZE), last_block_size);
    }
    mbedtls_md_finish(&md_ctx, hash); // 20B
    mbedtls_md_free(&md_ctx);
}

static void calc_ws_accept() {
    uint8_t hash[20] = {0};
    size_t ws_accept_len = 0;

    strncat(ws_key, CONFIG_WS_UUIT, strlen(CONFIG_WS_UUIT) + 1);
    calc_sha1((uint8_t *)ws_key, strlen(ws_key), hash);
    mbedtls_base64_encode((unsigned char *)ws_accept, sizeof(ws_accept), &ws_accept_len, hash, sizeof(hash));
}

static int ws_handshark() {
    int err = -1;
    char *header_start = (char *)rx_data;
    char *header_end = NULL;

    rx_len = recv(client_sock, rx_data, sizeof(rx_data), 0);
    if (rx_len <= 0) {
        close(client_sock);
        ESP_LOGE(TAG, "socket recv failed:%d", errno);
    } else {
        while (header_start[0] != '\r' && header_start[1] != '\n') {
            if ((0 == strncmp(header_start, "Connection: ", strlen("Connection: "))) ||                        // Connection: Upgrade
               (0 == strncmp(header_start, "Upgrade: ", strlen("Upgrade: "))) ||                               // Upgrade: websocket
               (0 == strncmp(header_start, "Sec-WebSocket-Version: ", strlen("Sec-WebSocket-Version: ")))) {   // Sec-WebSocket-Version: 13
                header_end = strstr(header_start, "\r\n");
                ESP_LOGI(TAG, "%.*s", header_end - header_start, header_start); 
            } else if (0 == strncmp(header_start, "Sec-WebSocket-Key: ", strlen("Sec-WebSocket-Key: "))) {     // Sec-WebSocket-Key: base64
                header_end = strstr(header_start, "\r\n");
                ESP_LOGI(TAG, "%.*s", header_end - header_start, header_start);

                strncpy(ws_key, header_start + strlen("Sec-WebSocket-Key: "), header_end - header_start - strlen("Sec-WebSocket-Key: "));
                calc_ws_accept();
                ESP_LOGI(TAG, "Sec-WebSocket-Accept: %s", ws_accept);

                tx_len = snprintf((char *)tx_data, sizeof(tx_data), CONFIG_WS_RESP, ws_accept);
                send(client_sock, tx_data, tx_len, 0);
                err = 0;
                break;
            }
            header_start = strstr(header_start, "\r\n");
            header_start += 2;
        }        
    }

    return err;
}

static void log_sample_cb(void *pvParameters) {
    int listen_sock = 0;
    int err = 0;
    struct sockaddr_in local_addr = {0};
    struct sockaddr_in client_addr = {0};
    socklen_t client_addr_len = sizeof(client_addr);
    uint8_t payload_len = 0, i = 0;

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "socket create failed:%d", errno);
        goto exit;
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(CONFIG_TCP_SERVER_PORT);
    err = bind(listen_sock, (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "socket bind failed:%d", errno);
        goto exit;
    }

    listen(listen_sock, 1);
    ESP_LOGI(TAG, "tcp listen, port:%u", CONFIG_TCP_SERVER_PORT);

    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_sock < 0) {
        ESP_LOGE(TAG, "socket accept failed:%d", errno);
        goto exit;
    }
    ESP_LOGI(TAG, "client connected, %s:%u", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);

    err = ws_handshark();
    if (err) {
        ESP_LOGE(TAG, "ws_handshark failed");
        goto exit;
    }
    ESP_LOGI(TAG, "ws_handshark success");

    while (1) {
        memset(rx_data, 0, sizeof(rx_data));

        rx_len = recv(client_sock, rx_data, 6, 0); // Fin,opcode,mask,payload_len,mask_key
        if (rx_len <= 0) {
            close(client_sock);
            esp_log_set_vprintf(&vprintf);
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            break;
        }

        if (0x08 == (rx_data[0] & 0x0f)) {
            close(client_sock);
            esp_log_set_vprintf(&vprintf);
            ESP_LOGW(TAG, "ws disconnect by peer");
            break;
        }

        payload_len = rx_data[1] & 0x7f;
        rx_len = recv(client_sock, rx_data + 6, payload_len, 0); // payload
        if (rx_len <= 0) {
            close(client_sock);
            esp_log_set_vprintf(&vprintf);
            ESP_LOGE(TAG, "socket recv failed:%d", errno);
            break;
        }
        for (i = 0; i < payload_len; i++) {
            rx_data[i + 6] ^= rx_data[(i % 4) + 2];
        }

        ESP_LOGI(TAG, "ws_frame_rx, fin:%u opcode:%u mask:%u payload_len:%u",
            (rx_data[0] & 0x80) ? 1 : 0, rx_data[0] & 0x0f, (rx_data[1] & 0x80) ? 1 : 0, payload_len);
        ESP_LOGI(TAG, "payload:%s", rx_data + 6);

        if (0 == strncmp((char *)rx_data + 6, "start", strlen("start"))) {
            esp_log_set_vprintf(&logSample_vprintf);
        }
        if (0 == strncmp((char *)rx_data + 6, "stop", strlen("stop"))) {
            esp_log_set_vprintf(&vprintf); // default
        }
    }

exit:
    vTaskDelete(NULL);
}

void logSample_init() {
    xTaskCreate(log_sample_cb, "log_sample", 4096, NULL, 5, NULL);
}
