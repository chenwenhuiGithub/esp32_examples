#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_websocket_client.h"


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_WS_SERVER_URI                    "ws://echo.websocket.events"
#define CONFIG_WSS_SERVER_URI                   "wss://echo.websocket.events"
#define CONFIG_USE_WSS                          0

#if CONFIG_USE_WSS == 1
extern const char echows_root_crt_start[]       asm("_binary_echows_root_crt_start");
extern const char echows_root_crt_end[]         asm("_binary_echows_root_crt_end");
extern const char client_crt_start[]            asm("_binary_client_crt_start");
extern const char client_crt_end[]              asm("_binary_client_crt_end");
extern const char client_priv_key_start[]       asm("_binary_client_priv_key_start");
extern const char client_priv_key_end[]         asm("_binary_client_priv_key_end");
#endif


static const char *TAG = "ws_client";
static esp_websocket_client_handle_t hd_ws_client = NULL;

static void websocket_event_handler(void *event_handler_arg, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_websocket_event_data_t *ws_data = (esp_websocket_event_data_t *)event_data;
    char send_data[16] = {0};
    char recv_data[128] = {0};
    uint32_t i = 0;

    switch (event_id) {
    case WEBSOCKET_EVENT_BEGIN:
        ESP_LOGI(TAG, "WEBSOCKET_EVENT_BEGIN");
        break;
    case WEBSOCKET_EVENT_CONNECTED:
        ESP_LOGI(TAG, "WEBSOCKET_EVENT_CONNECTED");
        for (i = 0; i < 10; i++) {
            send_data[i] = i + 0x30;
        }
        esp_websocket_client_send_text(hd_ws_client, send_data, strlen(send_data), 100);

        for (i = 0; i < sizeof(send_data); i++) {
            send_data[i] = i;
        }
        esp_websocket_client_send_bin(hd_ws_client, send_data, sizeof(send_data), 100);
    
        for (i = 0; i < sizeof(send_data); i++) {
            send_data[i] = i + 0x10;
        }
        esp_websocket_client_send_bin_partial(hd_ws_client, send_data, sizeof(send_data), 100);
        for (i = 0; i < sizeof(send_data); i++) {
            send_data[i] = i + 0x80;
        }
        esp_websocket_client_send_cont_msg(hd_ws_client, send_data, sizeof(send_data), 100);
        for (i = 0; i < sizeof(send_data); i++) {
            send_data[i] = i + 0xf0;
        }
        esp_websocket_client_send_cont_msg(hd_ws_client, send_data, sizeof(send_data), 100);
        esp_websocket_client_send_fin(hd_ws_client, 100);
        break;
    case WEBSOCKET_EVENT_DATA:
        ESP_LOGI(TAG, "WEBSOCKET_EVENT_DATA");
        ESP_LOGI(TAG, "opcode(0-subpkg,1-text,2-hex,8-disconn,9-ping,10-pong):0x%02x data_len:%d payload_len:%d payload_offset:%d",
            ws_data->op_code, ws_data->data_len, ws_data->payload_len, ws_data->payload_offset);
        if (HTTPD_WS_TYPE_TEXT == ws_data->op_code) {
            memcpy(recv_data, ws_data->data_ptr, ws_data->data_len);
            recv_data[ws_data->data_len] = 0;
            ESP_LOGI(TAG, "%s", recv_data);
        } else if (HTTPD_WS_TYPE_BINARY == ws_data->op_code) {
            ESP_LOG_BUFFER_HEX(TAG, ws_data->data_ptr, ws_data->data_len);
        } else if (HTTPD_WS_TYPE_CLOSE == ws_data->op_code) {
            ESP_LOGI(TAG, "disconnect reason:%d", (ws_data->data_ptr[0] << 8) + ws_data->data_ptr[1]);
        }
        break;
    case WEBSOCKET_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "WEBSOCKET_EVENT_DISCONNECTED");
        break;
    case WEBSOCKET_EVENT_CLOSED:
        ESP_LOGI(TAG, "WEBSOCKET_EVENT_CLOSED");
        break;
    case WEBSOCKET_EVENT_ERROR:
        ESP_LOGI(TAG, "WEBSOCKET_EVENT_ERROR");
        break;
    default:
        ESP_LOGW(TAG, "unknown event_id:%ld", event_id);
        break;
    }
}

static void ws_client_cb(void *pvParameters) {
    esp_websocket_client_config_t client_cfg = {0};
#if CONFIG_USE_WSS == 1
    client_cfg.uri = CONFIG_WSS_SERVER_URI;
    client_cfg.cert_pem = echows_root_crt_start;
    client_cfg.client_cert = client_crt_start;
    client_cfg.client_cert_len = client_crt_end - client_crt_start;
    client_cfg.client_key = client_priv_key_start;
    client_cfg.client_key_len = client_priv_key_end - client_priv_key_start;
    client_cfg.skip_cert_common_name_check = true;
#else
    client_cfg.uri = CONFIG_WS_SERVER_URI;
#endif

    hd_ws_client = esp_websocket_client_init(&client_cfg);
    esp_websocket_register_events(hd_ws_client, WEBSOCKET_EVENT_ANY, websocket_event_handler, NULL);
    esp_websocket_client_start(hd_ws_client);

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
            xTaskCreate(ws_client_cb, "ws_client", 4096, NULL, 5, NULL);
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
