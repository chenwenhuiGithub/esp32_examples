#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_WIFI_SCAN_AP_SIZE                10


static const char *TAG = "wifi_scan";
static wifi_ap_record_t ap_records[CONFIG_WIFI_SCAN_AP_SIZE] = {0};
static uint16_t ap_size = CONFIG_WIFI_SCAN_AP_SIZE;
static uint16_t ap_num = 0;

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    wifi_event_sta_connected_t *evt_sta_conn = NULL;
    wifi_event_sta_disconnected_t *evt_sta_disconn = NULL;
    wifi_event_home_channel_change_t *evt_channel_change = NULL;
    ip_event_got_ip_t *evt_got_ip = NULL;
    uint16_t i = 0;

    if (WIFI_EVENT == event_base) {
        switch (event_id) {
        case WIFI_EVENT_SCAN_DONE:
            ESP_LOGI(TAG, "WIFI_EVENT_SCAN_DONE");
            ap_size = CONFIG_WIFI_SCAN_AP_SIZE; // as input param
            esp_wifi_scan_get_ap_num(&ap_num);
            esp_wifi_scan_get_ap_records(&ap_size, ap_records);
            ESP_LOGI(TAG, "scanned:%u, saved:%u", ap_num, ap_size); // as output param, ap_size <= CONFIG_WIFI_SCAN_AP_SIZE
            for (i = 0; i < ap_size; i++) {
                ESP_LOGI(TAG, "bssid:"MACSTR" rssi:%d authmode:0x%02x channel:%2u ssid:%s",
                    MAC2STR(ap_records[i].bssid), ap_records[i].rssi, ap_records[i].authmode, ap_records[i].primary, ap_records[i].ssid);
            }
            break;
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "WIFI_EVENT_STA_START");
            ESP_LOGI(TAG, "start connect, %s:%s", CONFIG_WIFI_STA_SSID, CONFIG_WIFI_STA_PWD);
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
        case WIFI_EVENT_HOME_CHANNEL_CHANGE:
            evt_channel_change = (wifi_event_home_channel_change_t *)event_data;
            ESP_LOGI(TAG, "WIFI_EVENT_HOME_CHANNEL_CHANGE, home:%u->%u second:%u->%u",
                evt_channel_change->old_chan, evt_channel_change->new_chan, evt_channel_change->old_snd, evt_channel_change->new_snd);
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
        vTaskDelay(pdMS_TO_TICKS(30000));
        esp_wifi_scan_start(NULL, false);
    }
}
