#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "cJSON.h"
#include "cloud.h"
#include "tsl.h"
#include "ir.h"


static const char *TAG = "tsl";
static uint8_t s_rmtId = 0;
static uint8_t s_channelId = 0;

void tsl_recv_set_tsl(uint8_t *payload, uint32_t payload_len) {
    cJSON *json_root = cJSON_Parse((char *)payload);
    cJSON *json_params = cJSON_GetObjectItem(json_root, "params");
    cJSON *json_rmtId = cJSON_GetObjectItem(json_params, "rmtId");
    cJSON *json_channelId = cJSON_GetObjectItem(json_params, "channelId");
    uint8_t has_channelId = 0;

    if (json_rmtId) {
        s_rmtId = json_rmtId->valueint;
    }
    if (json_channelId) {
        s_channelId = json_channelId->valueint;
        has_channelId = 1;
    }
    cJSON_Delete(json_root);

    if (!has_channelId) {
        ESP_LOGI(TAG, "rmtId:%u", s_rmtId);
    } else {
        ESP_LOGI(TAG, "rmtId:%u, channelId:%u", s_rmtId, s_channelId);
        ir_recv(s_rmtId, s_channelId);
    }
}

void tsl_send_report_tsl() {
    cJSON *json_root = cJSON_CreateObject();
    cJSON *json_params = cJSON_CreateObject();
    char *buf = NULL;

    cJSON_AddStringToObject(json_root, "id", cloud_gen_msg_id());
    cJSON_AddStringToObject(json_root, "version", "1.0.0");
    cJSON_AddStringToObject(json_root, "method", "thing.event.property.post");
    cJSON_AddNumberToObject(json_params, "rmtId", s_rmtId);
    cJSON_AddNumberToObject(json_params, "channelId", s_channelId);
    cJSON_AddItemToObject(json_root, "params", json_params);
    buf = cJSON_PrintUnformatted(json_root);
    cloud_send_publish(CONFIG_TOPIC_TSL_POST, (uint8_t *)buf, strlen(buf), 1);
    free(buf);
    cJSON_Delete(json_root);
}
