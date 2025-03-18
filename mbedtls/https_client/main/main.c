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
#define CONFIG_HTTPS_SERVER_HOSTNAME            "howsmyssl.com"
#define CONFIG_HTTPS_SERVER_PORT                "443"

extern const char howsmyssl_root_crt_start[]    asm("_binary_howsmyssl_root_crt_start");
extern const char howsmyssl_root_crt_end[]      asm("_binary_howsmyssl_root_crt_end");


static const char *TAG = "https_client";
static const char get_req[] = "GET https://www."CONFIG_HTTPS_SERVER_HOSTNAME"/ HTTP/1.1\r\n"
                              "Host: "CONFIG_HTTPS_SERVER_HOSTNAME"\r\n"
                              "User-Agent: esp-idf/5.4.0 esp32\r\n"
                              "\r\n";

static void https_client_cb(void *pvParameters) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_net_context net_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_crt;
    uint8_t get_resp[1024] = {0};
    int ret = 0;
    const int client_ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384};
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
    mbedtls_net_init(&net_ctx);
    mbedtls_ssl_init(&ssl_ctx);
    mbedtls_ssl_config_init(&ssl_conf);
    mbedtls_x509_crt_init(&ca_crt);

    mbedtls_x509_crt_parse(&ca_crt, (unsigned char *)howsmyssl_root_crt_start, howsmyssl_root_crt_end - howsmyssl_root_crt_start);

    if ((ret = mbedtls_net_connect(&net_ctx, CONFIG_HTTPS_SERVER_HOSTNAME, CONFIG_HTTPS_SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        ESP_LOGE(TAG, "mbedtls_net_connect failed:-0x%x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, "mbedtls_net_connect success");

    mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_ciphersuites(&ssl_conf, client_ciphersuites);
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &ca_crt, NULL);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &ssl_conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup failed:-0x%x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, "mbedtls_ssl_setup success");
    
    mbedtls_ssl_set_hostname(&ssl_ctx, CONFIG_HTTPS_SERVER_HOSTNAME);
    mbedtls_ssl_set_bio(&ssl_ctx, &net_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake failed:-0x%x", -ret);
            goto exit;
        }
    }
    ESP_LOGI(TAG, "mbedtls_ssl_handshake success");

    if ((ret = mbedtls_ssl_get_verify_result(&ssl_ctx)) != 0) {
        ESP_LOGW(TAG, "mbedtls_ssl_get_verify_result failed:-0x%x", -ret);
    } else {
        ESP_LOGI(TAG, "mbedtls_ssl_get_verify_result success");
    }

    ESP_LOGI(TAG, "ciphersuite:%s", mbedtls_ssl_get_ciphersuite(&ssl_ctx));

    ESP_LOGI(TAG, "send HTTPS GET request");
    mbedtls_ssl_write(&ssl_ctx, (unsigned char *)get_req, strlen(get_req));
    while (1) {
        memset(get_resp, 0, sizeof(get_resp));
        ret = mbedtls_ssl_read(&ssl_ctx, get_resp, sizeof(get_resp));
        if (ret > 0) {
            ESP_LOGI(TAG, "%s", get_resp);
            // ESP_LOG_BUFFER_HEX(TAG, get_resp, ret);
        } else if (0 == ret || MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == ret) {
            ESP_LOGW(TAG, "connection closed by peer");
            break;
        } else {
            if (MBEDTLS_ERR_SSL_WANT_READ != ret && MBEDTLS_ERR_SSL_WANT_WRITE != ret) {
                ESP_LOGE(TAG, "mbedtls_ssl_read failed:-0x%x", -ret);
            }
            break;
        }
    }

exit:
    mbedtls_ssl_close_notify(&ssl_ctx);
    mbedtls_net_free(&net_ctx);
    mbedtls_x509_crt_free(&ca_crt);
    mbedtls_ssl_free(&ssl_ctx);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

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
            xTaskCreate(https_client_cb, "https_client", 8192, NULL, 5, NULL);
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
