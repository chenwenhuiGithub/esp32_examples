#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_client.h"


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_HTTP_SERVER_HOSTNAME             "httpbin.org"
#define CONFIG_HTTPS_SERVER_HOSTNAME            "howsmyssl.com"
#define CONFIG_HTTP_BUF_SIZE                    1024

extern const char howsmyssl_root_crt_start[]    asm("_binary_howsmyssl_root_crt_start");
extern const char howsmyssl_root_crt_end[]      asm("_binary_howsmyssl_root_crt_end");


static const char *TAG = "http_client";

static void test_http_get() {
    esp_err_t err = ESP_OK;
    esp_http_client_config_t client_cfg = {
        // .url = "http://"CONFIG_HTTP_SERVER_HOSTNAME"/stream-bytes/200", // "Transfer-Encoding":"chunked"
        .url = "http://"CONFIG_HTTP_SERVER_HOSTNAME"/get",
        // .host = CONFIG_HTTP_SERVER_HOSTNAME,
        // .path = "/get",
        // .transport_type = HTTP_TRANSPORT_OVER_TCP,
        .method = HTTP_METHOD_GET,
    };
    esp_http_client_handle_t hd_client = NULL;
    uint8_t resp_data[CONFIG_HTTP_BUF_SIZE] = {0};
    int resp_len = 0;
    int64_t content_len = 0;
    uint32_t i = 0;

    ESP_LOGI(TAG, "start http GET request");

    hd_client = esp_http_client_init(&client_cfg);
    if (NULL == hd_client) {
        ESP_LOGE(TAG, "http client init error");
        return;
    }

    // 1. setup tcp connect
    // 2. send GET request header
    //     write_len >= 0 - "Content-Length":write_len
    //     write_len < 0  - "Transfer-Encoding":"chunked"
    err = esp_http_client_open(hd_client, 0);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "http client open error:%d", err);
        return;
    }

    content_len = esp_http_client_fetch_headers(hd_client); // 3. recv GET response header
    if (content_len < 0) {
        ESP_LOGE(TAG, "http client fetch headers error:%lld", content_len);
        return;
    }

    if (!esp_http_client_is_chunked_response(hd_client)) {
        ESP_LOGI(TAG, "Content-Length: %lld", esp_http_client_get_content_length(hd_client));
        for (i = 0; i < content_len / CONFIG_HTTP_BUF_SIZE; i++) {
            esp_http_client_read(hd_client, (char *)resp_data, CONFIG_HTTP_BUF_SIZE); // 4. recv GET response body
            ESP_LOG_BUFFER_HEX(TAG, resp_data, CONFIG_HTTP_BUF_SIZE);
        }
        if (content_len % CONFIG_HTTP_BUF_SIZE) {
            esp_http_client_read(hd_client, (char *)resp_data, content_len % CONFIG_HTTP_BUF_SIZE);
            ESP_LOG_BUFFER_HEX(TAG, resp_data, content_len % CONFIG_HTTP_BUF_SIZE);
        }
    } else {
        ESP_LOGI(TAG, "Transfer-Encoding: chunked");
        while (1) {
            resp_len = esp_http_client_read(hd_client, (char *)resp_data, CONFIG_HTTP_BUF_SIZE);
            if (resp_len < 0) {
                ESP_LOGE(TAG, "http client read error:%d", resp_len);
                break;
            } else if (0 == resp_len) { // read complete
                break;
            } else {
                ESP_LOG_BUFFER_HEX(TAG, resp_data, resp_len);
            }
        }
    }

    // 5. close tcp connect
    // 6. free HTTP client resource
    esp_http_client_cleanup(hd_client); 
}

static void test_http_post() {
    esp_err_t err = ESP_OK;
    esp_http_client_config_t client_cfg = {
        .url = "http://"CONFIG_HTTP_SERVER_HOSTNAME"/post",
    };
    esp_http_client_handle_t hd_client = NULL;
    const char *post_data = "{\"field1\":\"value1\"}";
    uint8_t resp_data[CONFIG_HTTP_BUF_SIZE] = {0};
    int write_len = 0;
    int64_t content_len = 0;
    uint32_t i = 0;

    ESP_LOGI(TAG, "start http POST request");

    hd_client = esp_http_client_init(&client_cfg);
    if (NULL == hd_client) {
        ESP_LOGE(TAG, "http client init error");
        return;
    }

    esp_http_client_set_method(hd_client, HTTP_METHOD_POST);
    esp_http_client_set_header(hd_client, "Content-Type", "application/json");

    // 1. setup tcp connect
    // 2. send POST request header
    //     write_len >= 0 - "Content-Length":write_len
    //     write_len < 0  - "Transfer-Encoding":"chunked"
    err = esp_http_client_open(hd_client, strlen(post_data));
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "http client open error:%d", err);
        return;
    }

    write_len = esp_http_client_write(hd_client, post_data, strlen(post_data)); // 3. send POST request body
    if (write_len < 0) {
        ESP_LOGE(TAG, "http client write error:%d", write_len);
        return;
    }

    content_len = esp_http_client_fetch_headers(hd_client); // 4. recv POST response header
    if (content_len < 0) {
        ESP_LOGE(TAG, "http client fetch headers error:%lld", content_len);
        return;
    }

    ESP_LOGI(TAG, "Content-Length: %lld", esp_http_client_get_content_length(hd_client));
    for (i = 0; i < content_len / CONFIG_HTTP_BUF_SIZE; i++) {
        esp_http_client_read(hd_client, (char *)resp_data, CONFIG_HTTP_BUF_SIZE); // 5. recv POST response body
        ESP_LOG_BUFFER_HEX(TAG, resp_data, CONFIG_HTTP_BUF_SIZE);
    }
    if (content_len % CONFIG_HTTP_BUF_SIZE) {
        esp_http_client_read(hd_client, (char *)resp_data, content_len % CONFIG_HTTP_BUF_SIZE);
        ESP_LOG_BUFFER_HEX(TAG, resp_data, content_len % CONFIG_HTTP_BUF_SIZE);
    }

    // 6. close tcp connect
    // 7. free HTTP client resource
    esp_http_client_cleanup(hd_client); 
}

static void test_https_get() {
    esp_err_t err = ESP_OK;
    esp_http_client_config_t client_cfg = {
        // .url = "https://"CONFIG_HTTPS_SERVER_HOSTNAME,
        .host = CONFIG_HTTPS_SERVER_HOSTNAME,
        .path = "/",
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .method = HTTP_METHOD_GET,
        .cert_pem = howsmyssl_root_crt_start,
    };
    esp_http_client_handle_t hd_client = NULL;
    uint8_t resp_data[CONFIG_HTTP_BUF_SIZE] = {0};
    int resp_len = 0;
    int64_t content_len = 0;
    uint32_t i = 0;

    ESP_LOGI(TAG, "start https GET request");

    hd_client = esp_http_client_init(&client_cfg);
    if (NULL == hd_client) {
        ESP_LOGE(TAG, "http client init error");
        return;
    }

    // 1. setup tcp connect
    // 2. send GET request header
    //     write_len >= 0 - "Content-Length":write_len
    //     write_len < 0  - "Transfer-Encoding":"chunked"    
    err = esp_http_client_open(hd_client, 0);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "http client open error:%d", err);
        return;
    }

    content_len = esp_http_client_fetch_headers(hd_client); // 3. recv GET response header
    if (content_len < 0) {
        ESP_LOGE(TAG, "http client fetch headers error:%lld", content_len);
        return;
    }

    if (!esp_http_client_is_chunked_response(hd_client)) {
        ESP_LOGI(TAG, "Content-Length: %lld", esp_http_client_get_content_length(hd_client));
        for (i = 0; i < content_len / CONFIG_HTTP_BUF_SIZE; i++) {
            esp_http_client_read(hd_client, (char *)resp_data, CONFIG_HTTP_BUF_SIZE); // 4. recv GET response body
            ESP_LOG_BUFFER_HEX(TAG, resp_data, CONFIG_HTTP_BUF_SIZE);
        }
        if (content_len % CONFIG_HTTP_BUF_SIZE) {
            esp_http_client_read(hd_client, (char *)resp_data, content_len % CONFIG_HTTP_BUF_SIZE);
            ESP_LOG_BUFFER_HEX(TAG, resp_data, content_len % CONFIG_HTTP_BUF_SIZE);
        }
    } else {
        ESP_LOGI(TAG, "Transfer-Encoding: chunked");
        while (1) {
            resp_len = esp_http_client_read(hd_client, (char *)resp_data, CONFIG_HTTP_BUF_SIZE);
            if (resp_len < 0) {
                ESP_LOGE(TAG, "http client read error:%d", resp_len);
                break;
            } else if (0 == resp_len) { // read complete
                break;
            } else {
                ESP_LOG_BUFFER_HEX(TAG, resp_data, resp_len);
            }
        }
    }

    // 5. close tcp connect
    // 6. free HTTP client resource
    esp_http_client_cleanup(hd_client); 
}

static void http_client_cb(void *pvParameters) {
    test_http_get();
    test_http_post();
    test_https_get();

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
            xTaskCreate(http_client_cb, "http_client", 4096, NULL, 5, NULL);
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
