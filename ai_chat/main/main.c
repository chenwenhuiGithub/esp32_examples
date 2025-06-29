#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "oled.h"
#include "ir.h"
#include "sr.h"


#define CONFIG_GPIO_LED                         8
#define CONFIG_GPIO_BUTTON                      4

#define CONFIG_ADC_UNIT                         ADC_UNIT_1
#define CONFIG_ADC_CHANNEL                      ADC_CHANNEL_5 // GPIO6
#define CONFIG_ADC_ATTEN                        ADC_ATTEN_DB_12
#define CONFIG_ADC_BITWIDTH                     ADC_BITWIDTH_12


static const char *TAG = "ai_chat";
static uint8_t s_btn_pressed = 0;
static uint8_t s_led_onoff = 0;
static adc_oneshot_unit_handle_t s_hd_unit = NULL;
static adc_cali_handle_t s_hd_cali = NULL;


static void IRAM_ATTR gpio_isr_handler(void *arg) {
    s_btn_pressed = 1;
}

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

static void button_init() {
    gpio_config_t gpio_cfg = {0};

    gpio_cfg.pin_bit_mask = 1ULL << CONFIG_GPIO_BUTTON;
    gpio_cfg.mode = GPIO_MODE_INPUT;
    gpio_cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    gpio_cfg.intr_type = GPIO_INTR_NEGEDGE;
    gpio_config(&gpio_cfg);

    gpio_install_isr_service(0);
    gpio_set_intr_type(CONFIG_GPIO_BUTTON, GPIO_INTR_NEGEDGE);
    gpio_isr_handler_add(CONFIG_GPIO_BUTTON, gpio_isr_handler, NULL);
}

static esp_err_t adc_init() {
    esp_err_t err = ESP_OK;
    adc_oneshot_unit_init_cfg_t init_cfg = {
        .unit_id = CONFIG_ADC_UNIT,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };
    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = CONFIG_ADC_ATTEN,
        .bitwidth = CONFIG_ADC_BITWIDTH,
    };
    adc_cali_curve_fitting_config_t cali_cfg = { // esp32s3 support curve cali
        .unit_id = CONFIG_ADC_UNIT,
        .chan = CONFIG_ADC_CHANNEL,
        .atten = CONFIG_ADC_ATTEN,
        .bitwidth = CONFIG_ADC_BITWIDTH,
    };
    // adc_cali_line_fitting_config_t cali_cfg = { // esp32 support line cali
    //     .unit_id = CONFIG_ADC_UNIT,
    //     .atten = CONFIG_ADC_ATTEN,
    //     .bitwidth = CONFIG_ADC_BITWIDTH,
    // };

    err = adc_oneshot_new_unit(&init_cfg, &s_hd_unit);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "adc_oneshot_new_unit error:%d", err);
        return err;
    }

    err = adc_oneshot_config_channel(s_hd_unit, CONFIG_ADC_CHANNEL, &chan_cfg);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "adc_oneshot_config_channel error:%d", err);
        return err;
    }

    // err = adc_cali_create_scheme_line_fitting(&cali_cfg, &s_hd_cali);
    err = adc_cali_create_scheme_curve_fitting(&cali_cfg, &s_hd_cali);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "adc_cali_create_scheme_curve_fitting error:%d", err);
        return err;
    }

    return ESP_OK;
}


void app_main() {
    uint8_t hzline1_1[] = {0, 1, 2};
    uint8_t hzline1_2[] = {3, 4, 5};
    uint8_t hzline2[] = {6, 7, 8, 9, 10, 11};
    int adc_raw = 0, adc_cali = 0;

    led_init();
    button_init();
    oled_init();
    ir_init();
    adc_init();
    sr_init();

    oled_clear();
    oled_show_chinese(0, 4, hzline1_1, sizeof(hzline1_1));
    oled_show_chinese(80, 4, hzline1_2, sizeof(hzline1_2));
    oled_show_chinese(16, 6, hzline2, sizeof(hzline2));
    oled_show_line(50, 35, 75, 45, POINT_STAT_ON);
    oled_show_line(50, 45, 75, 35, POINT_STAT_ON);

    play_chinese("欢迎使用小爱同学");
    xTaskCreatePinnedToCore(feed_cb, "feed", 8 * 1024, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(detect_cb, "detect", 8 * 1024, NULL, 5, NULL, 1);

    heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);
    heap_caps_print_heap_info(MALLOC_CAP_SPIRAM);

    while (1) {
        if (s_btn_pressed) {
            ESP_LOGI(TAG, "btn pressed");
            if (!s_led_onoff) {
                s_led_onoff = 1;
            } else {
                s_led_onoff = 0;
            }
            gpio_set_level(CONFIG_GPIO_LED, s_led_onoff);

            adc_raw = 0;
            adc_oneshot_read(s_hd_unit, CONFIG_ADC_CHANNEL, &adc_raw);
            adc_cali_raw_to_voltage(s_hd_cali, adc_raw, &adc_cali);
            ESP_LOGI(TAG, "%4d mV 0x%03X", adc_cali, adc_raw);

            s_btn_pressed = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
