#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#define CONFIG_WIFI_SCAN_AP_SIZE                10
#define CONFIG_WIFI_CHANNEL_SIZE                14
#define CONFIG_WIFI_FRAME_FCS_LEN               4


static const char *TAG = "wifi_sniffer";
static wifi_ap_record_t ap_records[CONFIG_WIFI_SCAN_AP_SIZE] = {0};
static uint16_t ap_size = CONFIG_WIFI_SCAN_AP_SIZE;
static uint16_t ap_num = 0;
static uint8_t ap_channels[CONFIG_WIFI_CHANNEL_SIZE] = {0};
static uint8_t ap_channel_num = 0;

static void rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    ESP_LOGI(TAG, "recv pkt, type(0-mgmt,1-ctrl,2-data):%u channel:%u len:%u",
        type, pkt->rx_ctrl.channel, pkt->rx_ctrl.sig_len - CONFIG_WIFI_FRAME_FCS_LEN);
    // ESP_LOG_BUFFER_HEX(TAG, pkt->payload, pkt->rx_ctrl.sig_len - CONFIG_WIFI_FRAME_FCS_LEN);
}

static void sniffer_cb(void *pvParameters) {
    wifi_promiscuous_filter_t filter = {0};
    uint8_t i = 0;

    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_CTRL | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(rx_cb);

    while (1) {
        esp_wifi_set_channel(ap_channels[i], WIFI_SECOND_CHAN_NONE);
        esp_wifi_set_promiscuous(true);
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_wifi_set_promiscuous(false);
        i++;
        if (ap_channel_num == i) {
            i = 0;
        }
    }
}

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    wifi_event_home_channel_change_t *evt_channel_change = NULL;
    uint16_t i = 0, j = 0;

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
                for (j = 0; j < ap_channel_num; j++) {
                    if (ap_channels[j] == ap_records[i].primary) { // repeat channel
                        break;
                    }
                }
                if (j == ap_channel_num) { // new channel
                    ap_channels[ap_channel_num] = ap_records[i].primary;
                    ap_channel_num++;
                }                
            }
            xTaskCreate(sniffer_cb, "sniffer_task", 4096, NULL, 5, NULL);
            break;
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "WIFI_EVENT_STA_START");
            ESP_LOGI(TAG, "start scan");
            esp_wifi_scan_start(NULL, false);
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
}

void app_main(void) {
    esp_err_t err = ESP_OK;
    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    
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
    esp_wifi_start();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
