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


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_USE_WSS                          0

#if CONFIG_USE_WSS == 1
extern const uint8_t server_crt_start[]         asm("_binary_server_crt_start");
extern const uint8_t server_crt_end[]           asm("_binary_server_crt_end");
extern const uint8_t server_priv_key_start[]    asm("_binary_server_priv_key_start");
extern const uint8_t server_priv_key_end[]      asm("_binary_server_priv_key_end");
#endif


static esp_err_t get_echo_handler(httpd_req_t *req);

static const char *TAG = "ws_server";

static const httpd_uri_t uri_echo = {
    .uri       = "/echo",
    .method    = HTTP_GET,
    .handler   = get_echo_handler,
    .user_ctx  = NULL,
    .is_websocket = true,
    .handle_ws_control_frames = true
};

static esp_err_t get_echo_handler(httpd_req_t *req) {
    httpd_ws_frame_t ws_pkt = {0};
    uint8_t data[256] = {0};
    esp_err_t ret = ESP_OK;

    if (HTTP_GET == req->method) {
        ESP_LOGI(TAG, "handshake done");
        return ESP_OK;        
    }
    
    ws_pkt.payload = data;
    ret = httpd_ws_recv_frame(req, &ws_pkt, sizeof(data));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame failed:%d", ret);
        return ret;
    }

    ESP_LOGI(TAG, "final:%u fragmented:%u type(0-subpkg,1-text,2-hex,8-disconn,9-ping,10-pong):0x%02x len:%d",
        ws_pkt.final, ws_pkt.fragmented, ws_pkt.type, ws_pkt.len);
    if (HTTPD_WS_TYPE_TEXT == ws_pkt.type) {
        ws_pkt.payload[ws_pkt.len] = 0;
        ESP_LOGI(TAG, "%s", ws_pkt.payload);
    } else if (HTTPD_WS_TYPE_BINARY == ws_pkt.type) {
        ESP_LOG_BUFFER_HEX(TAG, ws_pkt.payload, ws_pkt.len);
    }

    ret = httpd_ws_send_frame(req, &ws_pkt);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_send_frame failed:%d", ret);
    }

    ws_pkt.type = HTTPD_WS_TYPE_TEXT;
    ws_pkt.len = strlen("hello world");
    memcpy(ws_pkt.payload, "hello world", strlen("hello world"));
    ret = httpd_ws_send_frame(req, &ws_pkt);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_send_frame failed:%d", ret);
    }

    return ESP_OK;
}

static void ws_server_cb(void *pvParameters) {
    httpd_handle_t hd_server = NULL;

#if CONFIG_USE_WSS == 1
    httpd_ssl_config_t httpd_cfg = HTTPD_SSL_CONFIG_DEFAULT();
    httpd_cfg.servercert = server_crt_start;
    httpd_cfg.servercert_len = server_crt_end - server_crt_start;
    httpd_cfg.prvtkey_pem = server_priv_key_start;
    httpd_cfg.prvtkey_len = server_priv_key_end - server_priv_key_start;
    if (httpd_ssl_start(&hd_server, &httpd_cfg) == ESP_OK) {
        httpd_register_uri_handler(hd_server, &uri_echo);
        ESP_LOGI(TAG, "start https server ok, port:%d", httpd_cfg.port_secure);
    } else {
        ESP_LOGE(TAG, "start https server failed");
    }
#else
    httpd_config_t httpd_cfg = HTTPD_DEFAULT_CONFIG();
    if (httpd_start(&hd_server, &httpd_cfg) == ESP_OK) {
        httpd_register_uri_handler(hd_server, &uri_echo);
        ESP_LOGI(TAG, "start http server ok, port:%d", httpd_cfg.server_port);
    } else {
        ESP_LOGE(TAG, "start http server failed");
    }
#endif

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
            xTaskCreate(ws_server_cb, "ws_server", 4096, NULL, 5, NULL);
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
