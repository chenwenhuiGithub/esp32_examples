#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2s_std.h"


#define CONFIG_GPIO_MAX98357_BCLK               46
#define CONFIG_GPIO_MAX98357_LRC                9
#define CONFIG_GPIO_MAX98357_DIN                3
#define CONFIG_GPIO_INMP441_SCK                 18
#define CONFIG_GPIO_INMP441_WS                  8
#define CONFIG_GPIO_INMP441_SD                  17

#define CONFIG_SAMPLE_RATE_TX                   16000
// #define CONFIG_SAMPLE_RATE_RX                   44100
#define CONFIG_SAMPLE_RATE_RX                   16000
#define CONFIG_SAMPLE_TIME                      3

#define CONFIG_BUF_SIZE                         4096


static const char *TAG = "i2s";
static i2s_chan_handle_t s_chan_hd_tx = NULL;
static i2s_chan_handle_t s_chan_hd_rx = NULL;
static uint8_t s_buf[CONFIG_BUF_SIZE] = {0};

static void i2s_echo_cb(void *pvParameters) {
    esp_err_t err = ESP_OK;
    size_t read = 0, write = 0, block = 0;
    int read_total = 0, write_total = 0;
    uint8_t *i2s_buf = NULL;
    size_t i2s_buf_size = CONFIG_SAMPLE_RATE_RX * 2 * CONFIG_SAMPLE_TIME; // 44.1K, 16bit, 1 slot, 3s
    uint8_t play_flag = 0;

    i2s_buf = malloc(i2s_buf_size);
    if (NULL == i2s_buf) {
        ESP_LOGE(TAG, "malloc error:%d", err);
        goto exit;
    }

    while (1) {
        err = i2s_channel_read(s_chan_hd_rx, s_buf, CONFIG_BUF_SIZE, &read, 500);
        if (ESP_OK == err) {
            if (read_total < i2s_buf_size) {
                block = (i2s_buf_size - read_total >= read) ? read : i2s_buf_size - read_total, 
                memcpy(i2s_buf + read_total, s_buf, block);
                read_total += block;                
            } else { // listen full(time = 3s), start play
                play_flag = 1;
            }
        } else if (ESP_ERR_TIMEOUT == err) {
            if (read_total > 0) { // listen end(time < 3s), start play
                play_flag = 1;
            }
        } else {
            ESP_LOGE(TAG, "i2s_channel_read error:%d", err);
            goto exit;
        }

        if (play_flag) {
            while (read_total > 0) {
                i2s_channel_write(s_chan_hd_tx, i2s_buf + write_total, CONFIG_BUF_SIZE, &write, 500);
                write_total += write;
                read_total -= write;
            }

            read_total = 0; // play complete, start next listen
            write_total = 0;
            play_flag = 0;
        }
    }

exit:
    free(i2s_buf);
    vTaskDelete(NULL);
}

void app_main(void) {
    esp_err_t err = ESP_OK;
    i2s_chan_config_t chan_cfg_tx = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    i2s_chan_config_t chan_cfg_rx = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_1, I2S_ROLE_MASTER);
    i2s_std_config_t std_cfg_tx = {
        .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(CONFIG_SAMPLE_RATE_TX),
        .slot_cfg = I2S_STD_MSB_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_32BIT, I2S_SLOT_MODE_MONO),
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
        .slot_cfg = I2S_STD_MSB_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
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
    std_cfg_tx.slot_cfg.slot_mask = I2S_STD_SLOT_LEFT;
    std_cfg_rx.slot_cfg.slot_mask = I2S_STD_SLOT_LEFT;

    err = i2s_new_channel(&chan_cfg_tx, &s_chan_hd_tx, NULL);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "i2s_new_channel tx error:%d", err);
        return;
    }
    err = i2s_new_channel(&chan_cfg_rx, NULL, &s_chan_hd_rx);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "i2s_new_channel rx error:%d", err);
        return;
    }
    
    i2s_channel_init_std_mode(s_chan_hd_tx, &std_cfg_tx);
    i2s_channel_init_std_mode(s_chan_hd_rx, &std_cfg_rx);
    i2s_channel_enable(s_chan_hd_tx);
    i2s_channel_enable(s_chan_hd_rx);

    xTaskCreate(i2s_echo_cb, "i2s_echo", 4096, NULL, 5, NULL);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
