#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "driver/i2s_std.h"
#include "esp_wn_iface.h"
#include "esp_wn_models.h"
#include "esp_afe_sr_iface.h"
#include "esp_afe_sr_models.h"
#include "esp_mn_iface.h"
#include "esp_mn_models.h"
#include "esp_mn_speech_commands.h"
#include "esp_tts_voice_template.h"
#include "esp_partition.h"
#include "model_path.h"


#define CONFIG_GPIO_LED                         8
#define CONFIG_GPIO_BTN                         4
#define CONFIG_GPIO_SPK_BCLK                    17
#define CONFIG_GPIO_SPK_LRC                     18
#define CONFIG_GPIO_SPK_DIN                     16
#define CONFIG_GPIO_MIC_SCK                     9
#define CONFIG_GPIO_MIC_WS                      3
#define CONFIG_GPIO_MIC_SD                      46

#define CONFIG_BTN_DEBOUNCE_MS                  20
#define CONFIG_BTN_DOUBLE_CLICK_MS              1000
#define CONFIG_BTN_LONG_PRESS_MS                5000

#define MN_CMDID_OPENTV                         1
#define MN_CMDID_CLOSETV                        2
#define MN_CMDID_ADDVOLUME                      3
#define MN_CMDID_SUBVOLUME                      4

#define CONFIG_MN_PROB_THRESHOLD                (0.8)


typedef enum {
    BTN_EVT_SINGLE_CLICK,
    BTN_EVT_DOUBLE_CLICK,
    BTN_EVT_LONG_PRESS
} btn_event_t;

typedef enum {
    BTN_STATE_IDLE,
    BTN_STATE_PRESSED,
    BTN_STATE_WAIT_DOUBLE,
    BTN_STATE_SECOND_PRESS,
    BTN_STATE_LONG_PRESS
} btn_state_t;

typedef struct {
    uint16_t id;
    char *cmd;
    char *ack;
} mn_cmd_info_t;


static const char *TAG = "ai_chat";
static i2s_chan_handle_t s_mic_hd = NULL;
static i2s_chan_handle_t s_spk_hd = NULL;
static srmodel_list_t *s_models = NULL;
const static esp_afe_sr_iface_t *s_afe_hd = NULL;
static esp_afe_sr_data_t *s_afe_data = NULL;
static esp_mn_iface_t *s_mn_hd = NULL;
static model_iface_data_t *s_if_data = NULL;
static esp_tts_handle_t *s_tts_hd = NULL;
static mn_cmd_info_t s_mn_cmds[] = {
    {MN_CMDID_OPENTV,       "da kai dian shi",          "电视已打开"},
    {MN_CMDID_CLOSETV,      "guan bi dian shi",         "电视已关闭"},
    {MN_CMDID_ADDVOLUME,    "sheng yin da dian",        NULL},
    {MN_CMDID_SUBVOLUME,    "sheng yin xiao dian",      NULL},
};


static void led_init() {
    gpio_config_t gpio_cfg = {0};

    gpio_cfg.pin_bit_mask = 1ULL << CONFIG_GPIO_LED;
    gpio_cfg.mode = GPIO_MODE_OUTPUT;
    gpio_cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    gpio_cfg.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&gpio_cfg);

    gpio_set_level(CONFIG_GPIO_LED, 1);
}

static void btn_init() {
    gpio_config_t gpio_cfg = {0};

    gpio_cfg.pin_bit_mask = 1ULL << CONFIG_GPIO_BTN;
    gpio_cfg.mode = GPIO_MODE_INPUT;
    gpio_cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    gpio_cfg.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&gpio_cfg);
}

static esp_err_t i2s_init() {
    esp_err_t ret = ESP_OK;
    i2s_chan_config_t mic_chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    i2s_std_config_t mic_std_cfg = { // INMP441
        .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(16000),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_24BIT, I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = CONFIG_GPIO_MIC_SCK,
            .ws   = CONFIG_GPIO_MIC_WS,
            .dout = I2S_GPIO_UNUSED,
            .din  = CONFIG_GPIO_MIC_SD
        },
    };
    i2s_chan_config_t spk_chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_1, I2S_ROLE_MASTER);
    i2s_std_config_t spk_std_cfg = { // MAX98357
        .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(16000),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = CONFIG_GPIO_SPK_BCLK,
            .ws   = CONFIG_GPIO_SPK_LRC,
            .dout = CONFIG_GPIO_SPK_DIN,
            .din  = I2S_GPIO_UNUSED
        },
    };

    mic_chan_cfg.auto_clear = true;
    mic_std_cfg.slot_cfg.slot_mask = I2S_STD_SLOT_LEFT;
    ret = i2s_new_channel(&mic_chan_cfg, NULL, &s_mic_hd); 
    if (ret) {
        ESP_LOGE(TAG, "i2s_new_channel mic failed:%d", ret);
    }
    i2s_channel_init_std_mode(s_mic_hd, &mic_std_cfg);
    i2s_channel_enable(s_mic_hd);

    spk_chan_cfg.auto_clear = true;
    spk_std_cfg.slot_cfg.slot_mask = I2S_STD_SLOT_LEFT;
    ret = i2s_new_channel(&spk_chan_cfg, &s_spk_hd, NULL); 
    if (ret) {
        ESP_LOGE(TAG, "i2s_new_channel spk failed:%d", ret);
    }
    i2s_channel_init_std_mode(s_spk_hd, &spk_std_cfg);
    i2s_channel_enable(s_spk_hd);

    return ret;
}

static esp_err_t sr_init() {
    esp_err_t ret = ESP_OK;
    afe_config_t *afe_cfg = NULL;
    const esp_partition_t *part = NULL;
    const void *voice_data = NULL;
    esp_partition_mmap_handle_t mmap_hd = 0;
    esp_tts_voice_t *tts_voice = NULL;
    char *mn_name = NULL;
    uint32_t i = 0;

    s_models = esp_srmodel_init("model");

    afe_cfg = afe_config_init("M", s_models, AFE_TYPE_SR, AFE_MODE_HIGH_PERF);
    afe_cfg->aec_init = false;
    afe_cfg->wakenet_init = true;
    afe_cfg->vad_init = true;
    afe_cfg->memory_alloc_mode = AFE_MEMORY_ALLOC_MORE_PSRAM;
    afe_cfg = afe_config_check(afe_cfg);
    s_afe_hd = esp_afe_handle_from_config(afe_cfg);
    s_afe_data = s_afe_hd->create_from_config(afe_cfg);
    afe_config_free(afe_cfg);

    part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "voice_data");
    esp_partition_mmap(part, 0, part->size, ESP_PARTITION_MMAP_DATA, &voice_data, &mmap_hd);
    tts_voice = esp_tts_voice_set_init(&esp_tts_voice_template, (int16_t *)voice_data);
    s_tts_hd = esp_tts_create(tts_voice);

    mn_name = esp_srmodel_filter(s_models, ESP_MN_PREFIX, ESP_MN_CHINESE);
    s_mn_hd = esp_mn_handle_from_name(mn_name);
    s_if_data = s_mn_hd->create(mn_name, 6000);
    esp_mn_commands_clear();
    for (i = 0; i < sizeof(s_mn_cmds) / sizeof(s_mn_cmds[0]); i++) {
        esp_mn_commands_add(s_mn_cmds[i].id, s_mn_cmds[i].cmd);
    }
    esp_mn_commands_update();
    s_mn_hd->print_active_speech_commands(s_if_data);

    return ret;
}

static void btn_evt_cb(btn_event_t evt) {
    switch (evt) {
        case BTN_EVT_SINGLE_CLICK:
            ESP_LOGI(TAG, "single click detected");
            break;
        case BTN_EVT_DOUBLE_CLICK:
            ESP_LOGI(TAG, "double click detected");
            break;
        case BTN_EVT_LONG_PRESS:
            ESP_LOGI(TAG, "long press detected");
            break;
        default:
            break;
    }
}

static void btn_detect_cb(void *pvParameters) {
    btn_state_t state = BTN_STATE_IDLE;
    uint32_t press_start_tick = 0;
    uint32_t release_tick = 0;
    uint8_t last_level = 1;
    uint8_t stable_level = 1;
    uint32_t debounce_tick = 0;

    while (1) {
        uint8_t current_level = gpio_get_level(CONFIG_GPIO_BTN);
        uint32_t current_tick = xTaskGetTickCount();

        if (current_level != last_level) {
            debounce_tick = current_tick;
            last_level = current_level;
        }

        if ((current_tick - debounce_tick) >= pdMS_TO_TICKS(CONFIG_BTN_DEBOUNCE_MS)) {
            if (current_level != stable_level) {
                stable_level = current_level;
            }
        }

        switch (state) {
            case BTN_STATE_IDLE:
                if (stable_level == 0) {
                    state = BTN_STATE_PRESSED;
                    press_start_tick = current_tick;
                }
                break;
            case BTN_STATE_PRESSED:
                if (stable_level == 1) {
                    uint32_t press_duration = (current_tick - press_start_tick) * portTICK_PERIOD_MS;
                    if (press_duration >= CONFIG_BTN_LONG_PRESS_MS) {
                        state = BTN_STATE_IDLE;
                    } else {
                        state = BTN_STATE_WAIT_DOUBLE;
                        release_tick = current_tick;
                    }
                } else {
                    uint32_t press_duration = (current_tick - press_start_tick) * portTICK_PERIOD_MS;
                    if (press_duration >= CONFIG_BTN_LONG_PRESS_MS) {
                        btn_evt_cb(BTN_EVT_LONG_PRESS);
                        state = BTN_STATE_LONG_PRESS;
                    }
                }
                break;
            case BTN_STATE_WAIT_DOUBLE:
                if (stable_level == 0) {
                    state = BTN_STATE_SECOND_PRESS;
                    press_start_tick = current_tick;
                } else {
                    uint32_t wait_duration = (current_tick - release_tick) * portTICK_PERIOD_MS;
                    if (wait_duration >= CONFIG_BTN_DOUBLE_CLICK_MS) {
                        btn_evt_cb(BTN_EVT_SINGLE_CLICK);
                        state = BTN_STATE_IDLE;
                    }
                }
                break;
            case BTN_STATE_SECOND_PRESS:
                if (stable_level == 1) {
                    btn_evt_cb(BTN_EVT_DOUBLE_CLICK);
                    state = BTN_STATE_IDLE;
                } else {
                    uint32_t press_duration = (current_tick - press_start_tick) * portTICK_PERIOD_MS;
                    if (press_duration >= CONFIG_BTN_LONG_PRESS_MS) {
                        btn_evt_cb(BTN_EVT_LONG_PRESS);
                        state = BTN_STATE_LONG_PRESS;
                    }
                }
                break;
            case BTN_STATE_LONG_PRESS:
                if (stable_level == 1) {
                    state = BTN_STATE_IDLE;
                }
                break;
            default:
                state = BTN_STATE_IDLE;
                break;
        }

        vTaskDelay(pdMS_TO_TICKS(CONFIG_BTN_DEBOUNCE_MS));
    }
}

static void play_chinese(char *string) {
    short *pcm_buf = NULL;
    size_t bytes_written = 0;

    if (esp_tts_parse_chinese(s_tts_hd, string)) {
        int len[1] = {0};
        do {
            pcm_buf = esp_tts_stream_play(s_tts_hd, len, 3); // speed: 0 - slowest, 5 - fastest
            i2s_channel_write(s_spk_hd, pcm_buf, len[0] * 2, &bytes_written, portMAX_DELAY);
        } while (len[0] > 0);
        // i2s_zero_dma_buffer(0);
    }
    // esp_tts_stream_reset(s_tts_hd);
}

static void afe_feed_cb(void *pvParameters) {
    int32_t *i2s_buf_32 = NULL;
    int16_t *afe_buf_16 = NULL;
    size_t bytes_read = 0, samples_read = 0, i = 0;
    int chunk_size = 0;

    chunk_size = s_afe_hd->get_feed_chunksize(s_afe_data);
    i2s_buf_32 = heap_caps_malloc(chunk_size * sizeof(int32_t), MALLOC_CAP_SPIRAM);
    afe_buf_16 = heap_caps_malloc(chunk_size * sizeof(int16_t), MALLOC_CAP_SPIRAM);
    if ((NULL == i2s_buf_32) || (NULL == afe_buf_16)) {
        ESP_LOGE(TAG, "malloc error");
        goto exit;
    }
    // ESP_LOGI(TAG, "chunk_size:%d", chunk_size);

    while (1) {
        i2s_channel_read(s_mic_hd, i2s_buf_32, chunk_size * sizeof(int32_t), &bytes_read, portMAX_DELAY);
        samples_read = bytes_read / sizeof(int32_t);
        for (i = 0; i < samples_read; i++) {
            afe_buf_16[i] = (int16_t)(i2s_buf_32[i] >> 16);
        }
        s_afe_hd->feed(s_afe_data, afe_buf_16);
    }

exit:
    vTaskDelete(NULL);
}

static void afe_detect_cb(void *pvParameters) {
    afe_fetch_result_t *fetch_ret = NULL;
    esp_mn_state_t mn_state = ESP_MN_STATE_DETECTING;
    esp_mn_results_t *mn_ret = NULL;
    uint8_t wakeup_flag = 0;

    while (1) {
        fetch_ret = s_afe_hd->fetch(s_afe_data); // timeout:2000ms
        if (!fetch_ret || ESP_FAIL == fetch_ret->ret_value) {
            ESP_LOGE(TAG, "s_afe_hd fetch error");
            goto exit;
        }

        if (WAKENET_DETECTED == fetch_ret->wakeup_state) {
            ESP_LOGI(TAG, "WAKENET_DETECTED");
	        s_mn_hd->clean(s_if_data);
            play_chinese("在呢");
        }

        if ((fetch_ret->raw_data_channels == 1) && (fetch_ret->wakeup_state == WAKENET_DETECTED)) {
            wakeup_flag = 1;
        } else if ((fetch_ret->raw_data_channels > 1) && (fetch_ret->wakeup_state == WAKENET_CHANNEL_VERIFIED)) {
            wakeup_flag = 1;
        }

        if (1 == wakeup_flag) {
            mn_state = s_mn_hd->detect(s_if_data, fetch_ret->data);
            if (ESP_MN_STATE_DETECTED == mn_state) {
                ESP_LOGI(TAG, "ESP_MN_STATE_DETECTED");
                mn_ret = s_mn_hd->get_results(s_if_data);
                // for (i = 0; i < mn_ret->num; i++) {
                //     ESP_LOGI(TAG, "MN DETECTED, TOP:%lu command_id:%d phrase_id:%d string:%s prob:%f",
                //         i, mn_ret->command_id[i], mn_ret->phrase_id[i], mn_ret->string, mn_ret->prob[i]);
                // }
                if (mn_ret->prob[0] > CONFIG_MN_PROB_THRESHOLD) {
                    if (s_mn_cmds[mn_ret->command_id[0]].ack) {
                        play_chinese(s_mn_cmds[mn_ret->command_id[0]].ack);
                    }
                } else {
                    // TODO: call baidu speech_sr platform ...
                }
            } else if (ESP_MN_STATE_TIMEOUT == mn_state) {
                ESP_LOGW(TAG, "ESP_MN_STATE_TIMEOUT");
                s_afe_hd->enable_wakenet(s_afe_data);
                wakeup_flag = 0;
                play_chinese("小米粒再见");
            } else { // ESP_MN_STATE_DETECTING

            }
        }
    }

exit:
    if (s_if_data) {
        s_mn_hd->destroy(s_if_data);
        s_if_data = NULL;
    }
    vTaskDelete(NULL);
}


void app_main() {
    led_init();
    btn_init();
    i2s_init();
    sr_init();

    xTaskCreate(&btn_detect_cb, "btn_detect", 2 * 1024, NULL, 5, NULL);
    xTaskCreatePinnedToCore(afe_feed_cb, "afe_feed", 8 * 1024, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(afe_detect_cb, "afe_detect", 8 * 1024, NULL, 5, NULL, 1);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
