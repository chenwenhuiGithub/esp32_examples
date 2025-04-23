#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"


#define CONFIG_ADC_UNIT                         ADC_UNIT_1
#define CONFIG_ADC_CHANNEL                      ADC_CHANNEL_6 // GPIO:34
#define CONFIG_ADC_ATTEN                        ADC_ATTEN_DB_12
#define CONFIG_ADC_BITWIDTH                     ADC_BITWIDTH_12


static const char *TAG = "adc";

void app_main(void) {
    esp_err_t err = ESP_OK;
    adc_oneshot_unit_handle_t hd_unit = NULL;
    adc_cali_handle_t hd_cali = NULL;
    adc_oneshot_unit_init_cfg_t init_cfg = {
        .unit_id = CONFIG_ADC_UNIT,
    };
    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = CONFIG_ADC_ATTEN,
        .bitwidth = CONFIG_ADC_BITWIDTH,
    };
    adc_cali_line_fitting_config_t cali_cfg = {
        .unit_id = CONFIG_ADC_UNIT,
        .atten = CONFIG_ADC_ATTEN,
        .bitwidth = CONFIG_ADC_BITWIDTH,
    };
    int raw_data = 0, voltage_mv = 0;

    err = adc_oneshot_new_unit(&init_cfg, &hd_unit);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "adc_oneshot_new_unit error:%d", err);
        return;
    }

    err = adc_oneshot_config_channel(hd_unit, CONFIG_ADC_CHANNEL, &chan_cfg);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "adc_oneshot_config_channel error:%d", err);
        return;
    }

    err = adc_cali_create_scheme_line_fitting(&cali_cfg, &hd_cali);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "adc_cali_create_scheme_line_fitting error:%d", err);
        return;
    }

    while (1) {
        raw_data = 0;
        err = adc_oneshot_read(hd_unit, CONFIG_ADC_CHANNEL, &raw_data);
        if (ESP_OK != err) {
            ESP_LOGE(TAG, "adc_oneshot_read error:%d", err);
        }
        err = adc_cali_raw_to_voltage(hd_cali, raw_data, &voltage_mv);
        if (ESP_OK != err) {
            ESP_LOGE(TAG, "adc_cali_raw_to_voltage error:%d", err);
        }
        ESP_LOGI(TAG, "raw_data:%d voltage:%d mV", raw_data, voltage_mv);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
