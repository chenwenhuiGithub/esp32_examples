#ifndef SR_H_
#define SR_H_

#include <stdint.h>

#define CONFIG_GPIO_MAX98357_BCLK               17
#define CONFIG_GPIO_MAX98357_LRC                18
#define CONFIG_GPIO_MAX98357_DIN                16
#define CONFIG_GPIO_INMP441_SCK                 9
#define CONFIG_GPIO_INMP441_WS                  3
#define CONFIG_GPIO_INMP441_SD                  46

#define CONFIG_SAMPLE_RATE_TX                   24000 // ???
#define CONFIG_SAMPLE_RATE_RX                   16000

#define CONFIG_CHANNEL_NUM_RX                   1
#define CONFIG_AFE_INPUT_FORMAT                 "M" // M - Mic, R - Record, N - Unused or Unknown, ???

#define MN_CMDID_OPENTV                         1
#define MN_CMDID_CLOSETV                        2
#define MN_CMDID_ADDVOLUME                      3
#define MN_CMDID_SUBVOLUME                      4

#define CONFIG_MN_PROB_THRESHOLD                (0.8)


esp_err_t sr_init();
void feed_cb(void *pvParameters);
void detect_cb(void *pvParameters);
void play_chinese(char *string);

#endif
