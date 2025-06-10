#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "driver/i2s_std.h"
#include "esp_wn_iface.h"
#include "esp_wn_models.h"
#include "esp_afe_sr_iface.h"
#include "esp_afe_sr_models.h"
#include "esp_mn_iface.h"
#include "esp_mn_models.h"
#include "esp_mn_speech_commands.h"
#include "esp_tts_voice_template.h"
#include "model_path.h"


#define CONFIG_GPIO_MAX98357_BCLK               46
#define CONFIG_GPIO_MAX98357_LRC                9
#define CONFIG_GPIO_MAX98357_DIN                3
#define CONFIG_GPIO_INMP441_SCK                 18
#define CONFIG_GPIO_INMP441_WS                  8
#define CONFIG_GPIO_INMP441_SD                  17

#define CONFIG_SAMPLE_RATE_TX                   16000
#define CONFIG_SAMPLE_RATE_RX                   16000

#define CONFIG_CHANNEL_NUM_RX                   1 // ???
#define CONFIG_AFE_INPUT_FORMAT                 "RM" // M - Mic, R - Record, N - Unused or Unknown, ???

typedef struct {
    uint16_t id;
    char *string;
} mn_cmd_info_t;


static const char *TAG = "ai_chat";
static i2s_chan_handle_t s_chan_hd_tx = NULL;
static i2s_chan_handle_t s_chan_hd_rx = NULL;
static srmodel_list_t *s_srmodels = NULL;
static esp_afe_sr_iface_t *s_afe_sr_if = NULL;
static esp_afe_sr_data_t *s_afe_sr_data = NULL;
static esp_tts_handle_t *s_tts_hd = NULL;
static mn_cmd_info_t s_mn_cmds[] = {
    {1, "da kai dian shi"},
    {2, "guan bi dian shi"},
    {3, "sheng yin da dian"},
    {4, "sheng yin xiao dian"},
};

static void play_chinese(char *string) {
    short *pcm_data = NULL;
    size_t bytes_write = 0;

    if (esp_tts_parse_chinese(s_tts_hd, string)) {
        int len[1] = {0};
        do {
            pcm_data = esp_tts_stream_play(s_tts_hd, len, 3);
            i2s_channel_write(s_chan_hd_tx, pcm_data, len[0] * 2, &bytes_write, portMAX_DELAY);
        } while (len[0] > 0);
    }
    esp_tts_stream_reset(s_tts_hd);
}

static void feed_cb(void *pvParameters) {
    int16_t *i2s_buf = NULL;
    uint32_t i2s_buf_size = 0, i = 0;
    int chunksize = 0;
    size_t bytes_read = 0;
    int32_t *tmp_buf = NULL;

    chunksize = s_afe_sr_if->get_feed_chunksize(s_afe_sr_data); // size of each channel samples(16-bit, not byte) per frame
    i2s_buf_size = chunksize * sizeof(int16_t) * CONFIG_CHANNEL_NUM_RX;
    i2s_buf = malloc(i2s_buf_size);
    if (i2s_buf == NULL) {
        ESP_LOGE(TAG, "malloc error");
        goto exit;
    }

    while (1) {
        i2s_channel_read(s_chan_hd_rx, i2s_buf, i2s_buf_size, &bytes_read, portMAX_DELAY);
        tmp_buf = (int32_t *)i2s_buf;
        for (i = 0; i < chunksize; i++) {
            tmp_buf[i] >>= 14; // ???
        }
        s_afe_sr_if->feed(s_afe_sr_data, i2s_buf);
    }

exit:
    vTaskDelete(NULL);
}

static void detect_cb(void *pvParameters) {
    char *mn_name = NULL;
    esp_mn_iface_t *mn_if = NULL;
    model_iface_data_t *if_data = NULL;
    afe_fetch_result_t *afe_fetch_ret = NULL;
    uint8_t wakeup_flag = 0;
    esp_mn_state_t mn_state = ESP_MN_STATE_DETECTING;
    esp_mn_results_t *mn_ret = NULL;
    uint32_t i = 0;

    mn_name = esp_srmodel_filter(s_srmodels, ESP_MN_PREFIX, ESP_MN_CHINESE);
    mn_if = esp_mn_handle_from_name(mn_name);
    if_data = mn_if->create(mn_name, 6000);
    esp_mn_commands_alloc(mn_if, if_data);
    for (i = 0; i < sizeof(s_mn_cmds) / sizeof(s_mn_cmds[0]); i++) {
        esp_mn_commands_add(s_mn_cmds[i].id, s_mn_cmds[i].string);
    }
    esp_mn_commands_update();

    while (1) {
        afe_fetch_ret = s_afe_sr_if->fetch(s_afe_sr_data); 
        if (!afe_fetch_ret || ESP_FAIL == afe_fetch_ret->ret_value) {
            ESP_LOGE(TAG, "s_afe_sr_if fetch error");
            goto exit;
        }

        if (WAKENET_DETECTED == afe_fetch_ret->wakeup_state) {
            ESP_LOGI(TAG, "WAKEWORD DETECTED");
	        mn_if->clean(if_data);
        }

        if ((afe_fetch_ret->raw_data_channels == 1) && (afe_fetch_ret->wakeup_state == WAKENET_DETECTED)) {
            wakeup_flag = 1;
        } else if ((afe_fetch_ret->raw_data_channels > 1) && (afe_fetch_ret->wakeup_state == WAKENET_CHANNEL_VERIFIED)) {
            wakeup_flag = 1;
        }

        if (wakeup_flag == 1) {
            play_chinese("在呢");
            mn_state = mn_if->detect(if_data, afe_fetch_ret->data);
            if (ESP_MN_STATE_DETECTED == mn_state) {
                mn_ret = mn_if->get_results(if_data);
                for (i = 0; i < mn_ret->num; i++) {
                    ESP_LOGI(TAG, "MN DETECTED, TOP:%lu command_id:%d phrase_id:%d string:%s prob:%f",
                        i, mn_ret->command_id[i], mn_ret->phrase_id[i], mn_ret->string, mn_ret->prob[i]);
                }
                // ..., use mn_ret->command_id[0]
            } else if (ESP_MN_STATE_TIMEOUT == mn_state) {
                s_afe_sr_if->enable_wakenet(s_afe_sr_data);
                wakeup_flag = 0;
                ESP_LOGW(TAG, "NM TIMEOUT");
                play_chinese("再见");
                continue;
            } else { // ESP_MN_STATE_DETECTING
                continue;
            }
        }
    }

exit:
    if (if_data) {
        mn_if->destroy(if_data);
        if_data = NULL;
    }
    vTaskDelete(NULL);
}

static esp_err_t i2s_init() {
    esp_err_t err = ESP_OK;
    i2s_chan_config_t chan_cfg_tx = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    i2s_chan_config_t chan_cfg_rx = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_1, I2S_ROLE_MASTER);
    i2s_std_config_t std_cfg_tx = {
        .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(CONFIG_SAMPLE_RATE_TX),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO), // ???
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = CONFIG_GPIO_MAX98357_BCLK,
            .ws   = CONFIG_GPIO_MAX98357_LRC, // ???
            .dout = CONFIG_GPIO_MAX98357_DIN,
            .din  = I2S_GPIO_UNUSED,
            .invert_flags = {
                .mclk_inv = false,
                .bclk_inv = false,
                .ws_inv   = false,
            },
        },
    };
    i2s_std_config_t std_cfg_rx = {
        .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(CONFIG_SAMPLE_RATE_RX),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO), // ???
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = CONFIG_GPIO_INMP441_SCK, // ???
            .ws   = CONFIG_GPIO_INMP441_WS,
            .dout = I2S_GPIO_UNUSED,
            .din  = CONFIG_GPIO_INMP441_SD,
            .invert_flags = {
                .mclk_inv = false,
                .bclk_inv = false,
                .ws_inv   = false,
            },
        },
    };

    err = i2s_new_channel(&chan_cfg_tx, &s_chan_hd_tx, NULL);
    err |= i2s_new_channel(&chan_cfg_rx, NULL, &s_chan_hd_rx);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "i2s_new_channel error:%d", err);
        return err;
    }
    i2s_channel_init_std_mode(s_chan_hd_tx, &std_cfg_tx);
    i2s_channel_init_std_mode(s_chan_hd_rx, &std_cfg_rx);
    i2s_channel_enable(s_chan_hd_tx);
    i2s_channel_enable(s_chan_hd_rx);

    return ESP_OK;
}

void app_main() {
    esp_err_t err = ESP_OK;
    afe_config_t *afe_cfg = NULL;
    const esp_partition_t *part = NULL;
    const void *part_data = NULL;
    esp_partition_mmap_handle_t part_mmap_hd = 0;
    esp_tts_voice_t *tts_voice = NULL;

    err = i2s_init();
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "i2s_init error:%d", err);
        return;
    }

    s_srmodels = esp_srmodel_init("model");
    if (NULL == s_srmodels) {
        ESP_LOGE(TAG, "esp_srmodel_init error");
        return;
    }
    afe_cfg = afe_config_init(CONFIG_AFE_INPUT_FORMAT, s_srmodels, AFE_TYPE_SR, AFE_MODE_LOW_COST);
    s_afe_sr_if = esp_afe_handle_from_config(afe_cfg);
    s_afe_sr_data = s_afe_sr_if->create_from_config(afe_cfg);
    afe_config_free(afe_cfg);

    part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "voice_data");
    if (NULL == part) { 
        ESP_LOGE(TAG, "No voice_data partition");
        return;
    }
    esp_partition_mmap(part, 0, part->size, ESP_PARTITION_MMAP_DATA, &part_data, &part_mmap_hd);
    tts_voice = esp_tts_voice_set_init(&esp_tts_voice_template, (int16_t *)part_data);
    s_tts_hd = esp_tts_create(tts_voice);

    play_chinese("欢迎使用小爱同学");

    xTaskCreatePinnedToCore(&feed_cb, "feed", 8 * 1024, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(&detect_cb, "detect", 8 * 1024, NULL, 5, NULL, 1);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
