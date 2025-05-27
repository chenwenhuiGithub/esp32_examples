#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "netcfg.h"
#include "cloud.h"
#include "ir.h"
#include "logSample.h"


#define CONFIG_WIFI_AP_IP                       "192.168.10.10"
#define CONFIG_WIFI_AP_NETMASK                  "255.255.255.0"
#define CONFIG_WIFI_AP_GW                       "192.168.10.10"
#define CONFIG_WIFI_AP_CHANNEL                  6
#define CONFIG_WIFI_AP_MAX_CONN                 2


static const char *TAG = "main";
static TimerHandle_t s_hd_timer = NULL;

static void wifi_reconnect_cb(TimerHandle_t xTimer) {
    ESP_LOGI(TAG, "wifi reconnect");
    esp_wifi_connect();
}

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    wifi_event_sta_connected_t *evt_sta_conn = NULL;
    wifi_event_sta_disconnected_t *evt_sta_disconn = NULL;
    wifi_event_ap_staconnected_t *evt_ap_staconn = NULL;
    wifi_event_ap_stadisconnected_t *evt_ap_stadisconn = NULL;
    wifi_event_home_channel_change_t *evt_channel_change = NULL;
    ip_event_got_ip_t *evt_got_ip = NULL;
    ip_event_ap_staipassigned_t *evt_assigned_ip = NULL;

    if (WIFI_EVENT == event_base) {
        switch (event_id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "WIFI_EVENT_STA_START");
            break;
        case WIFI_EVENT_STA_CONNECTED:
            evt_sta_conn = (wifi_event_sta_connected_t *)event_data;
            ESP_LOGI(TAG, "WIFI_EVENT_STA_CONNECTED, channel:%u authmode:0x%02x aid:0x%04x bssid:"MACSTR"",
                evt_sta_conn->channel, evt_sta_conn->authmode, evt_sta_conn->aid, MAC2STR(evt_sta_conn->bssid));
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            evt_sta_disconn = (wifi_event_sta_disconnected_t *)event_data; // reason:wifi_err_reason_t
            ESP_LOGE(TAG, "WIFI_EVENT_STA_DISCONNECTED, reason:0x%02x rssi:%d", evt_sta_disconn->reason, evt_sta_disconn->rssi);
            netcfg_set_netstat(NETSTAT_WIFI_NOT_CONNECTED);
            cloud_disconnect();
            xTimerReset(s_hd_timer, 0);
            break;
        case WIFI_EVENT_AP_START:
            ESP_LOGI(TAG, "WIFI_EVENT_AP_START");
            break;
        case WIFI_EVENT_AP_STACONNECTED:
            evt_ap_staconn = (wifi_event_ap_staconnected_t *)event_data;
            ESP_LOGI(TAG, "WIFI_EVENT_AP_STACONNECTED, aid:0x%04x mac:"MACSTR"", evt_ap_staconn->aid, MAC2STR(evt_ap_staconn->mac));
            break;
        case WIFI_EVENT_AP_STADISCONNECTED:
            evt_ap_stadisconn = (wifi_event_ap_stadisconnected_t *)event_data; // reason:wifi_err_reason_t
            ESP_LOGW(TAG, "WIFI_EVENT_AP_STADISCONNECTED, reason:0x%02x aid:0x%04x mac:"MACSTR"",
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
        case IP_EVENT_STA_GOT_IP:
            evt_got_ip = (ip_event_got_ip_t *)event_data;
            ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP, ip:"IPSTR" netmask:"IPSTR" gw:"IPSTR"",
                IP2STR(&evt_got_ip->ip_info.ip), IP2STR(&evt_got_ip->ip_info.netmask), IP2STR(&evt_got_ip->ip_info.gw));
            netcfg_set_netstat(NETSTAT_WIFI_CONNECTED);
            xTimerStop(s_hd_timer, 0); // netcfg give right ssid&pwd, stop reconnect
            cloud_connect();
            break;
        case IP_EVENT_STA_LOST_IP:
            ESP_LOGE(TAG, "IP_EVENT_STA_LOST_IP");
            netcfg_set_netstat(NETSTAT_WIFI_NOT_CONNECTED);
            cloud_disconnect();
            esp_wifi_disconnect();
            xTimerReset(s_hd_timer, 0);
            break;
        case IP_EVENT_AP_STAIPASSIGNED:
            evt_assigned_ip = (ip_event_ap_staipassigned_t *)event_data;
            ESP_LOGI(TAG, "IP_EVENT_AP_STAIPASSIGNED, ip:"IPSTR" mac:"MACSTR"", IP2STR(&evt_assigned_ip->ip), MAC2STR(evt_assigned_ip->mac));
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
    wifi_config_t sta_cfg = {0};
    wifi_config_t ap_cfg = {0};
    esp_netif_t *netif_ap = NULL;
    esp_netif_ip_info_t ap_ip_info = {0};
    uint8_t sta_mac[6] = {0};
    char task_mem[512] = {0};

    heap_caps_print_heap_info(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL);

    err = nvs_flash_init();
    if (ESP_ERR_NVS_NO_FREE_PAGES == err || ESP_ERR_NVS_NEW_VERSION_FOUND == err) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "nvs_flash_init error:%d", err);
        goto exit;
    }

    esp_event_loop_create_default();
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL);

    esp_netif_init();
    esp_netif_create_default_wifi_sta();
    netif_ap = esp_netif_create_default_wifi_ap();

    err = esp_wifi_init(&init_cfg);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "esp_wifi_init error:%d", err);
        goto exit;
    }

    netcfg_get_wifi_info((char *)sta_cfg.sta.ssid, (char *)sta_cfg.sta.password);
    esp_wifi_get_mac(ESP_IF_WIFI_STA, sta_mac);
    sprintf((char *)ap_cfg.ap.ssid, "ESP32_%02X%02X", sta_mac[4], sta_mac[5]);
    ap_cfg.ap.ssid_len = strlen((char *)ap_cfg.ap.ssid);
    ap_cfg.ap.channel = CONFIG_WIFI_AP_CHANNEL;
    ap_cfg.ap.max_connection = CONFIG_WIFI_AP_MAX_CONN;
    ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    ap_cfg.ap.ssid_hidden = 0;
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (sta_cfg.sta.ssid[0]) {
        esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    }
    esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_cfg);

    ESP_LOGI(TAG, "wifi info, ssid:%s password:%s ap_ssid:%s", sta_cfg.sta.ssid, sta_cfg.sta.password, ap_cfg.ap.ssid);
    err = esp_wifi_start();
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "esp_wifi_start error:%d", err);
        goto exit;
    }

    esp_netif_dhcps_stop(netif_ap);
    ap_ip_info.ip.addr = esp_ip4addr_aton(CONFIG_WIFI_AP_IP);
    ap_ip_info.netmask.addr = esp_ip4addr_aton(CONFIG_WIFI_AP_NETMASK);
    ap_ip_info.gw.addr = esp_ip4addr_aton(CONFIG_WIFI_AP_GW);
    esp_netif_set_ip_info(netif_ap, &ap_ip_info);
    err = esp_netif_dhcps_start(netif_ap);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "esp_netif_dhcps_start error:%d", err);
        goto exit;
    }

    if (sta_cfg.sta.ssid[0]) {
        esp_wifi_connect();
    }

    led_init();
    ir_init();
    netcfg_init();
    cloud_init();
    s_hd_timer = xTimerCreate("wifi_reconnect", pdMS_TO_TICKS(60000), pdTRUE, NULL, wifi_reconnect_cb); // 1min, wifi reconnect

    xTaskCreate(ir_recv_cb, "ir_recv", 2048, NULL, 3, NULL);
    xTaskCreate(netstat_cb, "netstat", 2048, NULL, 3, NULL);
    xTaskCreate(logSample_cb, "logSample", 4096, NULL, 2, NULL);

    while (1) {
        ESP_LOGI(TAG, "Task and Heap memory summary:");
        vTaskList(task_mem);
        printf("%s\n", task_mem);
		heap_caps_print_heap_info(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL);
        vTaskDelay(pdMS_TO_TICKS(30000)); // 30s, print memory info
    }

exit:
    vTaskDelete(NULL);
}
