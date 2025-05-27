#include "nvs_flash.h"
#include "nvs.h"
#include "esp_wifi.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "cJSON.h"
#include "ota.h"
#include "netcfg.h"


#define CONFIG_NETCFG_MAX_LEN_SSID                          32
#define CONFIG_NETCFG_MAX_LEN_PWD                           64
#define CONFIG_NETCFG_NVS_NAMESPACE                         "netcfg"
#define CONFIG_NETCFG_NVS_KEY_SSID                          "sta_ssid"
#define CONFIG_NETCFG_NVS_KEY_PWD                           "sta_pwd"


// gzip -k index.html
extern const uint8_t index_html_gz_start[]                  asm("_binary_index_html_gz_start");
extern const uint8_t index_html_gz_end[]                    asm("_binary_index_html_gz_end");

extern const uint8_t https_server_crt_start[]               asm("_binary_https_server_crt_start");
extern const uint8_t https_server_crt_end[]                 asm("_binary_https_server_crt_end");
extern const uint8_t https_server_priv_key_start[]          asm("_binary_https_server_priv_key_start");
extern const uint8_t https_server_priv_key_end[]            asm("_binary_https_server_priv_key_end");


static const char *TAG = "netcfg";
static nvs_handle_t s_hd_nvs = 0;
static netcfg_netstat_t s_netstat = NETSTAT_WIFI_NOT_CONNECTED;

void led_init() {
    gpio_config_t led_cfg = {0};

    led_cfg.intr_type = GPIO_INTR_DISABLE;
    led_cfg.pin_bit_mask = 1ULL << CONFIG_GPIO_NUM_NETCFG_LED;
    led_cfg.mode = GPIO_MODE_OUTPUT;
    led_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    led_cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_config(&led_cfg);

    gpio_set_level(CONFIG_GPIO_NUM_NETCFG_LED, 0); // 0 - off, 1 - on
}

void netstat_cb(void* parameter) {	
    while (1) {
        if (NETSTAT_WIFI_NOT_CONNECTED == s_netstat) {
            gpio_set_level(CONFIG_GPIO_NUM_NETCFG_LED, 1);
            vTaskDelay(pdMS_TO_TICKS(300));
            gpio_set_level(CONFIG_GPIO_NUM_NETCFG_LED, 0);
            vTaskDelay(pdMS_TO_TICKS(300));
        } else if (NETSTAT_WIFI_CONNECTED == s_netstat) {
            gpio_set_level(CONFIG_GPIO_NUM_NETCFG_LED, 1);
            vTaskDelay(pdMS_TO_TICKS(1000));
            gpio_set_level(CONFIG_GPIO_NUM_NETCFG_LED, 0);
            vTaskDelay(pdMS_TO_TICKS(1000));
        } else if (NETSTAT_CLOUD_CONNECTED == s_netstat) {
            gpio_set_level(CONFIG_GPIO_NUM_NETCFG_LED, 1);
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
}

static esp_err_t http_get_index_handler(httpd_req_t *req) {
    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return httpd_resp_send(req, (const char *)index_html_gz_start, index_html_gz_end - index_html_gz_start);
}

static esp_err_t http_post_cfgWifi_handler(httpd_req_t *req) {
    char post_data[256] = {0};
    cJSON *json_root = NULL, *json_ssid = NULL, *json_pwd = NULL;
    wifi_config_t sta_cfg = {0};

    httpd_req_recv(req, post_data, sizeof(post_data));
    ESP_LOGI(TAG, "cfgWifi:%s", post_data);

    json_root = cJSON_Parse(post_data);
    json_ssid = cJSON_GetObjectItem(json_root, "ssid");
    json_pwd = cJSON_GetObjectItem(json_root, "pwd");
    if (strlen(json_ssid->valuestring) > CONFIG_NETCFG_MAX_LEN_SSID || strlen(json_pwd->valuestring) > CONFIG_NETCFG_MAX_LEN_PWD) {
        ESP_LOGE(TAG, "ssid or pwd too long");
        httpd_resp_set_status(req, HTTPD_200);
        httpd_resp_send(req, "{\"code\":1, \"message\":\"ssid or pwd too long\"}", strlen("{\"code\":1, \"message\":\"ssid or pwd too long\"}"));
        cJSON_Delete(json_root);
        return ESP_FAIL;
    }
    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_send(req, "{\"code\":0, \"message\":\"success\"}", strlen("\"code\":0, {\"message\":\"success\"}"));

    memcpy(sta_cfg.sta.ssid, json_ssid->valuestring, strlen(json_ssid->valuestring));
    memcpy(sta_cfg.sta.password, json_pwd->valuestring, strlen(json_pwd->valuestring));
    cJSON_Delete(json_root);

    netcfg_set_wifi_info((char *)sta_cfg.sta.ssid, (char *)sta_cfg.sta.password);
    ESP_LOGI(TAG, "set wifi netcfg, %s:%s", sta_cfg.sta.ssid, sta_cfg.sta.password);

    netcfg_set_netstat(NETSTAT_WIFI_NOT_CONNECTED);
    esp_wifi_disconnect();
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    esp_wifi_connect();
    ESP_LOGI(TAG, "wifi start connect");

    return ESP_OK;
}

void netcfg_init() {
    esp_err_t err = ESP_OK;
    httpd_handle_t hd_httpd = NULL;
    httpd_ssl_config_t httpd_cfg = HTTPD_SSL_CONFIG_DEFAULT();
    const httpd_uri_t uri_get_index = {
        .uri       = "/",
        .method    = HTTP_GET,
        .handler   = http_get_index_handler,
        .user_ctx  = NULL,
    };
    const httpd_uri_t uri_post_cfgWifi = {
        .uri       = "/cfgWifi",
        .method    = HTTP_POST,
        .handler   = http_post_cfgWifi_handler,
        .user_ctx  = NULL,
    };
    const httpd_uri_t uri_post_ota = {
        .uri       = "/ota",
        .method    = HTTP_POST,
        .handler   = http_post_ota_handler,
        .user_ctx  = NULL,
    };

    httpd_cfg.servercert = https_server_crt_start;
    httpd_cfg.servercert_len = https_server_crt_end - https_server_crt_start;
    httpd_cfg.prvtkey_pem = https_server_priv_key_start;
    httpd_cfg.prvtkey_len = https_server_priv_key_end - https_server_priv_key_start;
    // httpd_cfg.cacert_pem = https_client_root_crt_start;
    // httpd_cfg.cacert_len = https_client_root_crt_end - https_client_root_crt_start;
    httpd_cfg.httpd.stack_size = 6144; // default:10240
    err = httpd_ssl_start(&hd_httpd, &httpd_cfg);
    if (ESP_OK == err) {
        httpd_register_uri_handler(hd_httpd, &uri_get_index);
        httpd_register_uri_handler(hd_httpd, &uri_post_cfgWifi);
        httpd_register_uri_handler(hd_httpd, &uri_post_ota);
        ESP_LOGI(TAG, "https server start success");
    } else {
        ESP_LOGE(TAG, "https server start error:%d", err);
    }
}

void netcfg_get_netstat(netcfg_netstat_t *stat) {
    *stat = s_netstat;
}

void netcfg_set_netstat(netcfg_netstat_t stat) {
    s_netstat = stat;
}

void netcfg_get_wifi_info(char *ssid, char *pwd) {
    size_t ssid_len = CONFIG_NETCFG_MAX_LEN_SSID;
    size_t pwd_len = CONFIG_NETCFG_MAX_LEN_PWD;

    nvs_open(CONFIG_NETCFG_NVS_NAMESPACE, NVS_READONLY, &s_hd_nvs);
    nvs_get_str(s_hd_nvs, CONFIG_NETCFG_NVS_KEY_SSID, ssid, &ssid_len);
    nvs_get_str(s_hd_nvs, CONFIG_NETCFG_NVS_KEY_PWD, pwd, &pwd_len);
    nvs_close(s_hd_nvs);
}

void netcfg_set_wifi_info(char *ssid, char *pwd) {
    nvs_open(CONFIG_NETCFG_NVS_NAMESPACE, NVS_READWRITE, &s_hd_nvs);
    nvs_set_str(s_hd_nvs, CONFIG_NETCFG_NVS_KEY_SSID, ssid);
    nvs_set_str(s_hd_nvs, CONFIG_NETCFG_NVS_KEY_PWD, pwd);
    nvs_commit(s_hd_nvs);
    nvs_close(s_hd_nvs);
}
