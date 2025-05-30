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
#define CONFIG_TCP_SERVER_IP                    "192.168.108.112"
#define CONFIG_TCP_SERVER_PORT                  60001
#define CONFIG_TCP_LOCAL_PORT                   60002
#define CONFIG_TCP_RECV_TIMEOUT_MS              3000


static const char *TAG = "tcp_client";

static void tcp_client_cb(void *pvParameters) {
    int sock = 0;
    int err = 0;
    int rx_len = 0;
    uint8_t rx_data[256] = {0};
    struct sockaddr_in local_addr = {0};
    struct sockaddr_in server_addr = {0};
    struct timeval tv = {
        .tv_sec = CONFIG_TCP_RECV_TIMEOUT_MS / 1000,
        .tv_usec = (CONFIG_TCP_RECV_TIMEOUT_MS % 1000) * 1000
    };

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket create failed:%d", errno);
        goto exit;
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(CONFIG_TCP_LOCAL_PORT);
    err = bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "socket bind failed:%d", errno);
        goto exit;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(CONFIG_TCP_SERVER_IP);
    server_addr.sin_port = htons(CONFIG_TCP_SERVER_PORT);
    ESP_LOGI(TAG, "socket start connect, %s:%u", CONFIG_TCP_SERVER_IP, CONFIG_TCP_SERVER_PORT);
    err = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "socket connect failed:%d", errno);
        goto exit;
    }
    ESP_LOGI(TAG, "socket connect success");

    err = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (err != 0) {
        ESP_LOGE(TAG, "socket setsockopt failed:%d", errno);
        goto exit;
    }

    err = send(sock, "hello world", strlen("hello world"), 0);
    if (err < 0) {
        ESP_LOGE(TAG, "socket send failed:%d", errno);
        goto exit;
    }

    while (1) {
        rx_len = recv(sock, rx_data, sizeof(rx_data), 0);
        if (rx_len < 0) {
            if (EAGAIN == errno || EWOULDBLOCK == errno) {
                ESP_LOGW(TAG, "socket recv timeout");
                continue;
            } else {
                ESP_LOGE(TAG, "socket recv failed:%d", errno);
                break;
            }
        } else if (0 == rx_len) {
            ESP_LOGE(TAG, "socket closed by peer");
            break;
        } else {
            err = send(sock, rx_data, rx_len, 0);
            if (err < 0) {
                ESP_LOGE(TAG, "socket send failed:%d", errno);
                break;
            }
        }
    }

exit:
    vTaskDelete(NULL);
}

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
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
            xTaskCreate(tcp_client_cb, "tcp_client", 4096, NULL, 5, NULL);
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
