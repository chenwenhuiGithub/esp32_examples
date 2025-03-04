#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/err.h"
#include "lwip/netdb.h"


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_NTP_SERVER_URL                   "pool.ntp.org"
#define CONFIG_NTP_SERVER_PORT                  123
#define CONFIG_NTP_LOCAL_PORT                   60001


typedef struct {  
    uint8_t flags;              // Leap Indicator, Version Number, Mode
    uint8_t stratum;            // Stratum level of the local clock
    uint8_t poll;               // Polling interval
    uint8_t precision;          // Precision of the local clock
    uint32_t rootDelay;         // Total round trip delay time
    uint32_t rootDispersion;    // Max error allowed from primary clock
    uint32_t refId;             // Reference clock identifier
    uint8_t refTimestamp[8];    // Reference time stamp
    uint8_t origTimestamp[8];   // Originate time stamp
    uint8_t recvTimestamp[8];   // Receive time stamp
    uint8_t sendTimestamp[8];   // Transmit time stamp
} ntp_packet_t;


static const char *TAG = "ntp";

static void get_server_ip(char *ip, uint32_t size) {
    struct addrinfo hints = {0}, *res = NULL;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(CONFIG_NTP_SERVER_URL, NULL, &hints, &res)) {
        ESP_LOGE(TAG, "socket getaddrinfo failed:%d", errno);
        return;        
    }
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, size);
    freeaddrinfo(res);
}

static void get_ntp_cb(void *pvParameters) {
    int sock = 0;
    struct sockaddr_in local_addr = {0};
    struct sockaddr_in server_addr = {0};
    socklen_t addr_len = sizeof(server_addr);
    ntp_packet_t ntp_packet = {
        .flags = (0x03 << 3) | 0x03 // NTP version 3, client mode
    };
    char server_ip[INET_ADDRSTRLEN] = {0};
    struct timeval tv = {0};
    struct tm *tm = NULL;
    char time_str[64] = {0};
    int rx_len = 0;
    uint32_t t3_s = 0, t3_us = 0;

    setenv("TZ", "CST-8", 1);
    tzset();

    get_server_ip(server_ip, sizeof(server_ip));
    ESP_LOGI(TAG, "%s:%s", CONFIG_NTP_SERVER_URL, server_ip);

    gettimeofday(&tv, NULL); // UTC
    tm = localtime(&tv.tv_sec); // UTC + TZ
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
    ESP_LOGI(TAG, "before:%s.%03lu", time_str, tv.tv_usec / 1000);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket create failed:%d", errno);
        goto exit;
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(CONFIG_NTP_LOCAL_PORT);
    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr))) {
        ESP_LOGE(TAG, "socket bind failed:%d", errno);
        goto exit;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CONFIG_NTP_SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    sendto(sock, &ntp_packet, sizeof(ntp_packet), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

    rx_len = recvfrom(sock, &ntp_packet, sizeof(ntp_packet), 0, (struct sockaddr *)&server_addr, &addr_len);
    if (rx_len <= 0) {
        ESP_LOGE(TAG, "socket recv failed:%d", errno);
        goto exit;
    }
    close(sock);

    // accurate = (t4 + t3 + t2 - t1) / 2
    //   simple = t3
    t3_s = (ntp_packet.sendTimestamp[0] << 24) | (ntp_packet.sendTimestamp[1] << 16) | (ntp_packet.sendTimestamp[2] << 8) | ntp_packet.sendTimestamp[3];
    t3_us = (ntp_packet.sendTimestamp[4] << 24) | (ntp_packet.sendTimestamp[5] << 16) | (ntp_packet.sendTimestamp[6] << 8) | ntp_packet.sendTimestamp[7];
    tv.tv_sec = t3_s - 2208988800; // 1900.01.01 00:00:00 -> 1970.01.01 00:00:00
    tv.tv_usec = ((uint64_t)t3_us * 1000000) >> 32; // fraction to microseconds  
    settimeofday(&tv, NULL); // UTC

    memset(time_str, 0, sizeof(time_str));
    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
    ESP_LOGI(TAG, " after:%s.%03lu", time_str, tv.tv_usec / 1000);

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
            xTaskCreate(get_ntp_cb, "get_ntp", 4096, NULL, 5, NULL);
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
