#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mqtt_client.h"


#define CONFIG_WIFI_STA_SSID                    "SolaxGuest"
#define CONFIG_WIFI_STA_PWD                     "solaxpower"
#define CONFIG_MQTT_SERVER_HOSTNAME             "test.mosquitto.org"
#define CONFIG_MQTT_PORT                        1883
#define CONFIG_MQTTS_PORT                       8884
#define CONFIG_USE_MQTTS                        1

#if CONFIG_USE_MQTTS == 1
// 1. download server root cert, https://test.mosquitto.org/ssl/mosquitto.org.crt
extern const char mosquitto_root_crt_start[]    asm("_binary_mosquitto_root_crt_start");
extern const char mosquitto_root_crt_end[]      asm("_binary_mosquitto_root_crt_end");
// 1. openssl genrsa -out client_priv.key 2048
// 2. openssl req -new -key client_priv.key -out client.csr -subj "/C=CN/ST=ZJ/L=HZ/O=esp32/OU=espressif/CN=*.espressif.com"
// 3. server root cert signature client cert, https://test.mosquitto.org/ssl/index.php
extern const char client_crt_start[]            asm("_binary_client_crt_start");
extern const char client_crt_end[]              asm("_binary_client_crt_end");
extern const char client_priv_key_start[]       asm("_binary_client_priv_key_start");
extern const char client_priv_key_end[]         asm("_binary_client_priv_key_end");
#endif


static const char *TAG = "mqtt";
static esp_mqtt_client_handle_t hd_client = NULL;
static int msg_id[3] = {0};

static void mqtt_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = event_data;

    switch (event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        msg_id[0] = esp_mqtt_client_subscribe(hd_client, "/cmd/down/sn123456", 0);
        msg_id[1] = esp_mqtt_client_subscribe(hd_client, "/echo/down/sn123456", 1);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGE(TAG, "MQTT_EVENT_DISCONNECTED");
        break;
    case MQTT_EVENT_SUBSCRIBED:
        if (event->msg_id == msg_id[0]) {
            ESP_LOGI(TAG, "/cmd/down/sn123456 subscribe success");
        }
        if (event->msg_id == msg_id[1]) {
            ESP_LOGI(TAG, "/echo/down/sn123456 subscribe success");
        }
        break;
    case MQTT_EVENT_PUBLISHED:
        if (event->msg_id == msg_id[2]) {
            ESP_LOGI(TAG, "/echo/up/sn123456 publish success");
        }
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        ESP_LOGI(TAG, "%.*s", event->topic_len, event->topic);
        ESP_LOG_BUFFER_HEX(TAG, event->data, event->data_len);
        if (!memcmp(event->topic, "/echo/down/sn123456", strlen("/echo/down/sn123456"))) {
            msg_id[2] = esp_mqtt_client_publish(hd_client, "/echo/up/sn123456", event->data, event->data_len, 1, 0);           
        }
        break;
    default:
        ESP_LOGW(TAG, "unknown MQTT_EVENT:%ld", event_id);
        break;
    }
}

static void mqtt_client_cb(void *pvParameters) {
    esp_mqtt_client_config_t client_cfg = {
#if CONFIG_USE_MQTTS == 1
        // .broker.address.uri = "mqtts://"CONFIG_MQTT_SERVER_HOSTNAME":8884",
        .broker.address.hostname = CONFIG_MQTT_SERVER_HOSTNAME,
        .broker.address.port = CONFIG_MQTTS_PORT,
        .broker.address.transport = MQTT_TRANSPORT_OVER_SSL,
        .broker.verification.certificate = mosquitto_root_crt_start,
        .broker.verification.certificate_len = mosquitto_root_crt_end - mosquitto_root_crt_start,
        .credentials.authentication.certificate = client_crt_start,
        .credentials.authentication.certificate_len = client_crt_end - client_crt_start,
        .credentials.authentication.key = client_priv_key_start,
        .credentials.authentication.key_len = client_priv_key_end - client_priv_key_start
#else
        .broker.address.uri = "mqtt://"CONFIG_MQTT_SERVER_HOSTNAME":1883",
        // .broker.address.hostname = CONFIG_MQTT_SERVER_HOSTNAME,
        // .broker.address.port = CONFIG_MQTT_PORT,
        // .broker.address.transport = MQTT_TRANSPORT_OVER_TCP
#endif
    };

    hd_client = esp_mqtt_client_init(&client_cfg);
    esp_mqtt_client_register_event(hd_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(hd_client);

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
            xTaskCreate(mqtt_client_cb, "mqtt_client", 4096, NULL, 5, NULL);
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