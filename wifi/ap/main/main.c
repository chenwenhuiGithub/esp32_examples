#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#define CONFIG_WIFI_AP_SSID                 "esp32_B5CC"
#define CONFIG_WIFI_AP_PWD                  "12345678"
#define CONFIG_WIFI_AP_CHANNEL              6
#define CONFIG_WIFI_AP_MAX_STA              3


static const char *TAG = "wifi_ap";

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    wifi_event_ap_staconnected_t *evt_ap_staconn = NULL;
    wifi_event_ap_stadisconnected_t *evt_ap_stadisconn = NULL;
    wifi_event_home_channel_change_t *evt_channel_change = NULL;
    ip_event_ap_staipassigned_t *evt_ap_ip_assigned = NULL;

    if (WIFI_EVENT == event_base) {
        switch (event_id) {
        case WIFI_EVENT_AP_START:
            ESP_LOGI(TAG, "WIFI_EVENT_AP_START");
            ESP_LOGI(TAG, "ssid:%s channel:%u", CONFIG_WIFI_AP_SSID, CONFIG_WIFI_AP_CHANNEL);
            break;
        case WIFI_EVENT_AP_STOP:
            ESP_LOGI(TAG, "WIFI_EVENT_AP_STOP");
            break;
        case WIFI_EVENT_AP_STACONNECTED:
            evt_ap_staconn = (wifi_event_ap_staconnected_t *)event_data;
            ESP_LOGI(TAG, "WIFI_EVENT_AP_STACONNECTED, aid:0x%04x mac:"MACSTR"", evt_ap_staconn->aid, MAC2STR(evt_ap_staconn->mac));
            break;
        case WIFI_EVENT_AP_STADISCONNECTED:
            evt_ap_stadisconn = (wifi_event_ap_stadisconnected_t *)event_data; // reason:wifi_err_reason_t
            ESP_LOGI(TAG, "WIFI_EVENT_AP_STADISCONNECTED, reason:0x%02x aid:0x%04x mac:"MACSTR"",
                evt_ap_stadisconn->reason, evt_ap_stadisconn->aid, MAC2STR(evt_ap_stadisconn->mac));
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
        case IP_EVENT_AP_STAIPASSIGNED:
            evt_ap_ip_assigned = (ip_event_ap_staipassigned_t *)event_data;
            ESP_LOGI(TAG, "IP_EVENT_AP_STAIPASSIGNED, ip:"IPSTR" mac:"MACSTR"", IP2STR(&evt_ap_ip_assigned->ip), MAC2STR(evt_ap_ip_assigned->mac));
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
    wifi_config_t ap_cfg = {
        .ap = {
            .ssid = CONFIG_WIFI_AP_SSID,
            .ssid_len = strlen(CONFIG_WIFI_AP_SSID),
            .password = CONFIG_WIFI_AP_PWD,
            .channel = CONFIG_WIFI_AP_CHANNEL,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .ssid_hidden = 0, // broadcast SSID
            .max_connection = CONFIG_WIFI_AP_MAX_STA,
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
    esp_netif_create_default_wifi_ap();

    esp_wifi_init(&init_cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
    esp_wifi_start();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
