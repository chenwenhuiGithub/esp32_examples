#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ssd1306.h"


static const char *TAG = "i2c";

void app_main(void) {
    esp_err_t err = ESP_OK;
    uint8_t hzline1_1[] = {0, 1, 2};
    uint8_t hzline1_2[] = {3, 4, 5};
    uint8_t hzline2[] = {6, 7, 8, 9, 10, 11};

    vTaskDelay(pdMS_TO_TICKS(1000));

    err = oled_init();
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "oled_init err:%d", err);
        return;
    }
    oled_clear();
    oled_show_char(0, 0, 'a', CHAR_SIZE_6X8);
    oled_show_char(121, 0, 'Z', CHAR_SIZE_6X8);
    oled_show_string(50, 0, "i2c", CHAR_SIZE_6X8);
    oled_show_string(0, 1, "abcdefg01234567890XYZ", CHAR_SIZE_6X8);
    oled_show_string(40, 2, "!#$&()?@<>=", CHAR_SIZE_8X16);
    oled_show_chinese(0, 4, hzline1_1, sizeof(hzline1_1));
    oled_show_chinese(80, 4, hzline1_2, sizeof(hzline1_2));
    oled_show_chinese(16, 6, hzline2, sizeof(hzline2));

    oled_show_point(20, 2, POINT_STAT_ON);
    oled_show_point(20, 5, POINT_STAT_ON);
    oled_show_point(100, 2, POINT_STAT_ON);
    oled_show_point(100, 5, POINT_STAT_ON);
    oled_show_line(3, 24, 35, 24, POINT_STAT_ON);
    oled_show_line(20, 20, 20, 30, POINT_STAT_ON);
    oled_show_line(50, 35, 75, 45, POINT_STAT_ON);
    oled_show_line(50, 45, 75, 35, POINT_STAT_ON);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
