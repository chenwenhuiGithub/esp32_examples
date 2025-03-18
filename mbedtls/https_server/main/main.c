#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl_ciphersuites.h"


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_HTTPS_SERVER_PORT                "443"

extern const char server_crt_start[]            asm("_binary_server_crt_start");
extern const char server_crt_end[]              asm("_binary_server_crt_end");
extern const char server_priv_key_start[]       asm("_binary_server_priv_key_start");
extern const char server_priv_key_end[]         asm("_binary_server_priv_key_end");


static const char *TAG = "https_server";
static const char get_resp[] = "HTTP/1.1 200 OK\r\n"
                               "Content-Type: text/html\r\n"
                               "\r\n"
                               "<h2>MbedTLS HTTPS Server</h2>\r\n"
                               "<p>hello world</p>\r\n";

static void https_server_cb(void *pvParameters) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt server_crt;
    mbedtls_pk_context pk_ctx;
    mbedtls_net_context listen_fd, client_fd;
    uint8_t get_req[1024] = {0};
    int ret = 0;
    const int *support_ciphersuites = NULL;

    ESP_LOGI(TAG, "supported ciphersuites:");
    support_ciphersuites = mbedtls_ssl_list_ciphersuites();
    while (*support_ciphersuites) {
        ESP_LOGI(TAG, "0x%04X %s", (*support_ciphersuites), mbedtls_ssl_get_ciphersuite_name(*support_ciphersuites));
        support_ciphersuites++;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    mbedtls_ssl_init(&ssl_ctx);
    mbedtls_ssl_config_init(&ssl_conf);
    mbedtls_x509_crt_init(&server_crt);
    mbedtls_pk_init(&pk_ctx);
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);

    mbedtls_x509_crt_parse(&server_crt, (unsigned char *)server_crt_start, server_crt_end - server_crt_start);
    mbedtls_pk_parse_key(&pk_ctx, (unsigned char *)server_priv_key_start, server_priv_key_end - server_priv_key_start, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_net_bind(&listen_fd, NULL, CONFIG_HTTPS_SERVER_PORT, MBEDTLS_NET_PROTO_TCP);

    mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_own_cert(&ssl_conf, &server_crt, &pk_ctx);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &ssl_conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup failed:-0x%x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, "mbedtls_ssl_setup success");
    
    ESP_LOGI(TAG, "wait client connect");
    mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    ESP_LOGI(TAG, "mbedtls_net_accept success");

    mbedtls_ssl_set_bio(&ssl_ctx, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake failed:-0x%x", -ret);
            goto exit;
        }
    }
    ESP_LOGI(TAG, "mbedtls_ssl_handshake success");

    ESP_LOGI(TAG, "ciphersuite:%s", mbedtls_ssl_get_ciphersuite(&ssl_ctx));

    ESP_LOGI(TAG, "recv HTTPS GET request");
    ret = mbedtls_ssl_read(&ssl_ctx, get_req, sizeof(get_req));
    if (ret > 0) {
        ESP_LOGI(TAG, "%s", get_req);
        // ESP_LOG_BUFFER_HEX(TAG, get_req, ret);

        ESP_LOGI(TAG, "send HTTPS GET response");
        mbedtls_ssl_write(&ssl_ctx, (unsigned char *)get_resp, strlen(get_resp));
    }

exit:
    mbedtls_ssl_close_notify(&ssl_ctx);
    mbedtls_x509_crt_free(&server_crt);
    mbedtls_ssl_free(&ssl_ctx);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&listen_fd);
    mbedtls_net_free(&client_fd);

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
            xTaskCreate(https_server_cb, "https_server", 8192, NULL, 5, NULL);
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
