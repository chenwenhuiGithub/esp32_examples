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
#define CONFIG_HTTP_BUF_SIZE                    1024
#define CONFIG_USE_HTTPS                        0

#if CONFIG_USE_HTTPS == 1
extern const uint8_t server_crt_start[]         asm("_binary_server_crt_start");
extern const uint8_t server_crt_end[]           asm("_binary_server_crt_end");
extern const uint8_t server_priv_key_start[]    asm("_binary_server_priv_key_start");
extern const uint8_t server_priv_key_end[]      asm("_binary_server_priv_key_end");
#endif

static esp_err_t get_hello_handler(httpd_req_t *req);
static esp_err_t post_echo_handler(httpd_req_t *req);


static const char *TAG = "http_server";

static const httpd_uri_t uri_get_hello = {
    .uri       = "/hello",
    .method    = HTTP_GET,
    .handler   = get_hello_handler,
    .user_ctx  = "hello world",
};

static const httpd_uri_t uri_post_echo = {
    .uri       = "/echo",
    .method    = HTTP_POST,
    .handler   = post_echo_handler,
    .user_ctx  = NULL,
};

static esp_err_t get_hello_handler(httpd_req_t *req) {
    char data[128] = {0};
    char val_k1[32] = {0};
    char val_k2[32] = {0};
    size_t data_len = 0;
    const char *resp_body = (const char*)req->user_ctx;

    data_len = httpd_req_get_hdr_value_len(req, "Host"); // parse GET request header
    if (data_len > 0) {
        httpd_req_get_hdr_value_str(req, "Host", data, sizeof(data));
        ESP_LOGI(TAG, "Host:%s", data);
    }

    data_len = httpd_req_get_hdr_value_len(req, "Request-Header");
    if (data_len > 0) {
        httpd_req_get_hdr_value_str(req, "Request-Header", data, sizeof(data));
        ESP_LOGI(TAG, "Request-Header:%s", data);
    }

    data_len = httpd_req_get_url_query_len(req); // parse GET request query
    if (data_len > 0) {
        httpd_req_get_url_query_str(req, data, sizeof(data));
        httpd_query_key_value(data, "k1", val_k1, sizeof(val_k1));
        ESP_LOGI(TAG, "k1:%s", val_k1);
        httpd_query_key_value(data, "k2", val_k2, sizeof(val_k2));
        ESP_LOGI(TAG, "k2:%s", val_k2);
    }

    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_set_hdr(req, "Response-Header", "RH_abcd");
    httpd_resp_set_type(req, HTTPD_TYPE_TEXT);
    httpd_resp_send(req, resp_body, strlen(resp_body));

    return ESP_OK;
}

static esp_err_t post_echo_handler(httpd_req_t *req) {
    uint8_t data[CONFIG_HTTP_BUF_SIZE] = {0};
    size_t data_len = 0, content_len = 0;
    char content_type[64] = {0};
    uint32_t i = 0;

    data_len = httpd_req_get_hdr_value_len(req, "Host"); // parse POST request header
    if (data_len > 0) {
        httpd_req_get_hdr_value_str(req, "Host", (char *)data, sizeof(data));
        ESP_LOGI(TAG, "Host:%s", data);
    }

    data_len = httpd_req_get_hdr_value_len(req, "Request-Header");
    if (data_len > 0) {
        httpd_req_get_hdr_value_str(req, "Request-Header", (char *)data, sizeof(data));
        ESP_LOGI(TAG, "Request-Header:%s", data);
    }

    data_len = httpd_req_get_hdr_value_len(req, "Content-Type");
    if (data_len > 0) {
        httpd_req_get_hdr_value_str(req, "Content-Type", content_type, sizeof(content_type));
        ESP_LOGI(TAG, "Content-Type:%s", content_type);
    }

    content_len = req->content_len;
    for (i = 0; i < content_len / CONFIG_HTTP_BUF_SIZE; i++) {
        httpd_req_recv(req, (char *)data, CONFIG_HTTP_BUF_SIZE); // recv POST request body
        ESP_LOG_BUFFER_HEX(TAG, data, CONFIG_HTTP_BUF_SIZE);
    }
    if (content_len % CONFIG_HTTP_BUF_SIZE) {
        httpd_req_recv(req, (char *)data, content_len % CONFIG_HTTP_BUF_SIZE);
        ESP_LOG_BUFFER_HEX(TAG, data, content_len % CONFIG_HTTP_BUF_SIZE);
    }

    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_set_hdr(req, "Response-Header", "RH_abcd");
    httpd_resp_set_type(req, content_type);
    httpd_resp_send(req, (char *)data, content_len);

    return ESP_OK;
}

static void http_server_cb(void *pvParameters) {
    esp_err_t err = ESP_OK;
    httpd_handle_t hd_httpd = NULL;

#if CONFIG_USE_HTTPS == 1
    httpd_ssl_config_t httpd_ssl_cfg = HTTPD_SSL_CONFIG_DEFAULT();
    httpd_ssl_cfg.servercert = server_crt_start;
    httpd_ssl_cfg.servercert_len = server_crt_end - server_crt_start;
    httpd_ssl_cfg.prvtkey_pem = server_priv_key_start;
    httpd_ssl_cfg.prvtkey_len = server_priv_key_end - server_priv_key_start;
    err = httpd_ssl_start(&hd_httpd, &httpd_ssl_cfg);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "start https server error:%d", err);
        goto exit;
    }
    httpd_register_uri_handler(hd_httpd, &uri_get_hello);
    httpd_register_uri_handler(hd_httpd, &uri_post_echo);
    ESP_LOGI(TAG, "start https server success, port:%d", httpd_ssl_cfg.port_secure);
#else
    httpd_config_t httpd_cfg = HTTPD_DEFAULT_CONFIG();
    err = httpd_start(&hd_httpd, &httpd_cfg);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "start http server error:%d", err);
        goto exit;
    }
    httpd_register_uri_handler(hd_httpd, &uri_get_hello);
    httpd_register_uri_handler(hd_httpd, &uri_post_echo);
    ESP_LOGI(TAG, "start http server success, port:%d", httpd_cfg.server_port);
#endif

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
            xTaskCreate(http_server_cb, "http_server", 4096, NULL, 5, NULL);
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
