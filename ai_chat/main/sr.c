#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2s_std.h"
#include "esp_partition.h"
#include "esp_wn_iface.h"
#include "esp_wn_models.h"
#include "esp_afe_sr_iface.h"
#include "esp_afe_sr_models.h"
#include "esp_mn_iface.h"
#include "esp_mn_models.h"
#include "esp_mn_speech_commands.h"
#include "esp_tts_voice_template.h"
#include "model_path.h"
#include "esp_log.h"
#include "esp_err.h"
#include "sr.h"
#include "ir.h"


typedef struct {
    uint16_t id;
    char *cmd;
    char *ack;
} mn_cmd_info_t;


static const char *TAG = "sr";
static i2s_chan_handle_t s_chan_hd_tx = NULL;
static i2s_chan_handle_t s_chan_hd_rx = NULL;
static srmodel_list_t *s_srmodels = NULL;
static esp_afe_sr_iface_t *s_afe_sr_if = NULL;
static esp_afe_sr_data_t *s_afe_sr_data = NULL;
static esp_mn_iface_t *s_mn_if = NULL;
static model_iface_data_t *s_if_data = NULL;
static esp_tts_handle_t *s_tts_hd = NULL;
static uint8_t s_volume = 70; // 0 ~ 100
static mn_cmd_info_t s_mn_cmds[] = {
    {MN_CMDID_OPENTV,       "da kai dian shi",          "正在打开电视"},
    {MN_CMDID_CLOSETV,      "guan bi dian shi",         "正在关闭电视"},
    {MN_CMDID_ADDVOLUME,    "sheng yin da dian",        NULL},
    {MN_CMDID_SUBVOLUME,    "sheng yin xiao dian",      NULL},
};

void play_chinese(char *string) {
    short *src_buf = NULL;
    int32_t *dst_buf = NULL;
    size_t dst_buf_size = 0, bytes_written = 0, i = 0;
    int32_t factor = (int32_t)(pow(s_volume / 100.0f, 2) * 65536);
    int len = 0;
    int64_t temp = 0;

    if (esp_tts_parse_chinese(s_tts_hd, string)) {
        do {
            src_buf = esp_tts_stream_play(s_tts_hd, &len, 1); // speed: 0 - slowest, 5 - fastest
            if (len <= 0) {
                break;
            }
            dst_buf_size = len * sizeof(int32_t);
            dst_buf = heap_caps_malloc(dst_buf_size, MALLOC_CAP_SPIRAM);
            for (i = 0; i < len; i++) {
                temp = (int64_t)src_buf[i] * factor;
                if (temp > INT32_MAX) {
                    dst_buf[i] = INT32_MAX;
                } else if (temp < INT32_MIN) {
                    dst_buf[i] = INT32_MIN;
                } else {
                    dst_buf[i] = (int32_t)temp;
                }
            }
            i2s_channel_write(s_chan_hd_tx, dst_buf, dst_buf_size, &bytes_written, portMAX_DELAY);
            heap_caps_free(dst_buf);
        } while (len > 0);
    }
    // esp_tts_stream_reset(s_tts_hd);
}

void feed_cb(void *pvParameters) {
    int32_t *src_buf = NULL;
    int16_t *dst_buf = NULL;
    size_t src_buf_size = 0, dst_buf_size = 0, bytes_read = 0, samples_read = 0, i = 0;
    int chunk_size = 0;
    int32_t temp = 0;

    chunk_size = s_afe_sr_if->get_feed_chunksize(s_afe_sr_data); // size of each channel samples(16-bit, not byte) per frame
    src_buf_size = chunk_size * sizeof(int32_t) * CONFIG_CHANNEL_NUM_RX;
    dst_buf_size = chunk_size * sizeof(int16_t) * CONFIG_CHANNEL_NUM_RX;
    ESP_LOGI(TAG, "chunk_size:%d src_buf_size:%u dst_buf_size:%u", chunk_size, src_buf_size, dst_buf_size);
    src_buf = malloc(src_buf_size);
    dst_buf = malloc(dst_buf_size);
    if ((NULL == src_buf) || (NULL == dst_buf)) {
        ESP_LOGE(TAG, "malloc error");
        goto exit;
    }

    while (1) {
        i2s_channel_read(s_chan_hd_rx, src_buf, src_buf_size, &bytes_read, portMAX_DELAY);
        samples_read = bytes_read / sizeof(int32_t);
        for (i = 0; i < samples_read; i++) {
            temp = src_buf[i] >> 12;
            if (temp > INT16_MAX) {
                dst_buf[i] = INT16_MAX;
            } else if (temp < INT16_MIN) {
                dst_buf[i] = INT16_MIN;
            } else {
                dst_buf[i] = (int16_t)temp;
            }
        }
        s_afe_sr_if->feed(s_afe_sr_data, dst_buf);
    }

exit:
    vTaskDelete(NULL);
}

void detect_cb(void *pvParameters) {
    afe_fetch_result_t *afe_fetch_ret = NULL;
    esp_mn_state_t mn_state = ESP_MN_STATE_DETECTING;
    esp_mn_results_t *mn_ret = NULL;
    uint8_t wakeup_flag = 0, last_wakeup_flag = 0;

    while (1) {
        afe_fetch_ret = s_afe_sr_if->fetch_with_delay(s_afe_sr_data, portMAX_DELAY); // ???
        if (!afe_fetch_ret || ESP_FAIL == afe_fetch_ret->ret_value) {
            ESP_LOGE(TAG, "s_afe_sr_if fetch error");
            goto exit;
        }

        if (WAKENET_DETECTED == afe_fetch_ret->wakeup_state) {
            ESP_LOGI(TAG, "WAKEWORD DETECTED");
	        s_mn_if->clean(s_if_data);
        }

        if ((afe_fetch_ret->raw_data_channels == 1) && (afe_fetch_ret->wakeup_state == WAKENET_DETECTED)) {
            wakeup_flag = 1;
        } else if ((afe_fetch_ret->raw_data_channels > 1) && (afe_fetch_ret->wakeup_state == WAKENET_CHANNEL_VERIFIED)) {
            wakeup_flag = 1;
        }

        if (1 == wakeup_flag) {
            if (0 == last_wakeup_flag) {
                play_chinese("在呢");
                last_wakeup_flag = 1;
            }
            mn_state = s_mn_if->detect(s_if_data, afe_fetch_ret->data);
            if (ESP_MN_STATE_DETECTED == mn_state) {
                mn_ret = s_mn_if->get_results(s_if_data);
                // for (i = 0; i < mn_ret->num; i++) {
                //     ESP_LOGI(TAG, "MN DETECTED, TOP:%lu command_id:%d phrase_id:%d string:%s prob:%f",
                //         i, mn_ret->command_id[i], mn_ret->phrase_id[i], mn_ret->string, mn_ret->prob[i]);
                // }
                if (mn_ret->prob[0] > CONFIG_MN_PROB_THRESHOLD) {
                    if (s_mn_cmds[mn_ret->command_id[0]].ack) {
                        play_chinese(s_mn_cmds[mn_ret->command_id[0]].ack);
                    }

                    switch (mn_ret->command_id[0]) {
                    case MN_CMDID_OPENTV:
                    case MN_CMDID_CLOSETV:
                        ir_recv(RMTID_TV, CHANNELID_POWER);
                        break;
                    case MN_CMDID_ADDVOLUME:
                        if (s_volume < 100) {
                            s_volume += 10;
                        }
                        ir_recv(RMTID_TV, CHANNELID_VOLUME_ADD);
                        break;
                    case MN_CMDID_SUBVOLUME:
                        if (s_volume >= 10) {
                            s_volume -= 10;
                        }
                        ir_recv(RMTID_TV, CHANNELID_VOLUME_SUB);
                        break;
                    default:
                        ESP_LOGW(TAG, "unknown command_id:%d", mn_ret->command_id[0]);
                        break;
                    }
                } else {
                    // TODO: call baidu speech_sr platform ...
                }
            } else if (ESP_MN_STATE_TIMEOUT == mn_state) {
                s_afe_sr_if->enable_wakenet(s_afe_sr_data);
                wakeup_flag = 0;
                last_wakeup_flag = 0;
                ESP_LOGW(TAG, "NM TIMEOUT");
                play_chinese("小米粒再见");
            } else { // ESP_MN_STATE_DETECTING

            }
        }
    }

exit:
    if (s_if_data) {
        s_mn_if->destroy(s_if_data);
        s_if_data = NULL;
    }
    vTaskDelete(NULL);
}

static esp_err_t i2s_init() {
    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    i2s_std_config_t std_cfg = {
        .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(CONFIG_SAMPLE_RATE_TX),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_32BIT, I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = CONFIG_GPIO_MAX98357_BCLK,
            .ws   = CONFIG_GPIO_MAX98357_LRC,
            .dout = CONFIG_GPIO_MAX98357_DIN,
            .din  = I2S_GPIO_UNUSED,
            .invert_flags = {
                .mclk_inv = false,
                .bclk_inv = false,
                .ws_inv   = false,
            },
        },
    };

    chan_cfg.auto_clear_after_cb = true;
    std_cfg.slot_cfg.slot_mask = I2S_STD_SLOT_LEFT;
    std_cfg.slot_cfg.left_align = false; // ???
    i2s_new_channel(&chan_cfg, &s_chan_hd_tx, NULL); // MAX98357
    i2s_channel_init_std_mode(s_chan_hd_tx, &std_cfg);

    chan_cfg.id = I2S_NUM_1;
    std_cfg.clk_cfg.sample_rate_hz = CONFIG_SAMPLE_RATE_RX;
    std_cfg.gpio_cfg.bclk = CONFIG_GPIO_INMP441_SCK;
    std_cfg.gpio_cfg.ws = CONFIG_GPIO_INMP441_WS;
    std_cfg.gpio_cfg.dout = I2S_GPIO_UNUSED;
    std_cfg.gpio_cfg.din = CONFIG_GPIO_INMP441_SD;
    i2s_new_channel(&chan_cfg, NULL, &s_chan_hd_rx); // INMP441
    i2s_channel_init_std_mode(s_chan_hd_rx, &std_cfg);
    
    i2s_channel_enable(s_chan_hd_tx);
    i2s_channel_enable(s_chan_hd_rx);

    return ESP_OK;
}

esp_err_t sr_init() {
    esp_err_t err = ESP_OK;
    afe_config_t *afe_cfg = NULL;
    const esp_partition_t *part = NULL;
    const void *part_data = NULL;
    esp_partition_mmap_handle_t part_mmap_hd = 0;
    esp_tts_voice_t *tts_voice = NULL;
    char *mn_name = NULL;
    uint32_t i = 0;

    err = i2s_init();
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "i2s_init error:%d", err);
        return err;
    }

    s_srmodels = esp_srmodel_init("model");
    if (NULL == s_srmodels) {
        ESP_LOGE(TAG, "esp_srmodel_init error");
        return ESP_FAIL;
    }

    afe_cfg = afe_config_init(CONFIG_AFE_INPUT_FORMAT, s_srmodels, AFE_TYPE_SR, AFE_MODE_LOW_COST);
    afe_cfg->memory_alloc_mode = AFE_MEMORY_ALLOC_MORE_PSRAM; // ???
    s_afe_sr_if = esp_afe_handle_from_config(afe_cfg);
    s_afe_sr_data = s_afe_sr_if->create_from_config(afe_cfg);
    afe_config_free(afe_cfg);

    part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "voice_data");
    esp_partition_mmap(part, 0, part->size, ESP_PARTITION_MMAP_DATA, &part_data, &part_mmap_hd);
    tts_voice = esp_tts_voice_set_init(&esp_tts_voice_template, (int16_t *)part_data);
    s_tts_hd = esp_tts_create(tts_voice);

    mn_name = esp_srmodel_filter(s_srmodels, ESP_MN_PREFIX, ESP_MN_CHINESE);
    s_mn_if = esp_mn_handle_from_name(mn_name);
    s_if_data = s_mn_if->create(mn_name, 6000);
    esp_mn_commands_clear();
    for (i = 0; i < sizeof(s_mn_cmds) / sizeof(s_mn_cmds[0]); i++) {
        esp_mn_commands_add(s_mn_cmds[i].id, s_mn_cmds[i].cmd);
    }
    esp_mn_commands_update();
    s_mn_if->print_active_speech_commands(s_if_data);

    return ESP_OK;
}
