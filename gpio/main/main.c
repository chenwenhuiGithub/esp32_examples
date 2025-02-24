#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"

#define CONFIG_GPIO_LED                         2
#define CONFIG_GPIO_SWITCH                      4

static int g_switch = 0;

void app_main(void) {
    gpio_config_t gpio_cfg = {0};

    gpio_cfg.pin_bit_mask = 1ULL << CONFIG_GPIO_LED;
    gpio_cfg.mode = GPIO_MODE_OUTPUT;
    gpio_cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    gpio_cfg.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&gpio_cfg);

    gpio_cfg.pin_bit_mask = 1ULL << CONFIG_GPIO_SWITCH;
    gpio_cfg.mode = GPIO_MODE_INPUT;
    gpio_cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    gpio_cfg.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&gpio_cfg);

    gpio_set_level(CONFIG_GPIO_LED, 0); // 0 - off, 1 - on

    while (1) {
        g_switch = gpio_get_level(CONFIG_GPIO_SWITCH);
        gpio_set_level(CONFIG_GPIO_LED, g_switch);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
