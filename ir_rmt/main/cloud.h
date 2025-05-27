#ifndef CLOUD_H_
#define CLOUD_H_

#include <stdint.h>

#define CONFIG_CLOUD_PK                             "a1GCY1V8kBX"
#define CONFIG_CLOUD_DK                             "ovHa9DNEP3ma1WZs6aNE"
#define CONFIG_CLOUD_DS                             "e36742c9698a83e63cf05c691a4bcc07"
#define CONFIG_MQTT_HOSTNAME                        CONFIG_CLOUD_PK".iot-as-mqtt.cn-shanghai.aliyuncs.com"
#define CONFIG_MQTT_PORT                            1883
#define CONFIG_MQTT_KEEP_ALIVE                      300 // 5min
#define CONFIG_TOPIC_TSL_POST                       "/sys/"CONFIG_CLOUD_PK"/"CONFIG_CLOUD_DK"/thing/event/property/post"
#define CONFIG_TOPIC_TSL_POST_REPLY                 "/sys/"CONFIG_CLOUD_PK"/"CONFIG_CLOUD_DK"/thing/event/property/post_reply"
#define CONFIG_TOPIC_TSL_SET                        "/sys/"CONFIG_CLOUD_PK"/"CONFIG_CLOUD_DK"/thing/service/property/set"
#define CONFIG_TOPIC_TSL_SET_REPLY                  "/sys/"CONFIG_CLOUD_PK"/"CONFIG_CLOUD_DK"/thing/service/property/set_reply"
#define CONFIG_TOPIC_OTA_TASK                       "/ota/device/upgrade/"CONFIG_CLOUD_PK"/"CONFIG_CLOUD_DK
#define CONFIG_TOPIC_OTA_PROGRESS                   "/ota/device/progress/"CONFIG_CLOUD_PK"/"CONFIG_CLOUD_DK
#define CONFIG_TOPIC_OTA_REPORT                     "/ota/device/inform/"CONFIG_CLOUD_PK"/"CONFIG_CLOUD_DK

void cloud_init();
char *cloud_gen_msg_id();
esp_err_t cloud_connect();
esp_err_t cloud_disconnect();
void cloud_publish(char *topic, uint8_t *payload, uint32_t payload_len, uint8_t qos);
void cloud_recv_tsl(uint8_t *payload, uint32_t payload_len);
void cloud_send_tsl();

#endif
