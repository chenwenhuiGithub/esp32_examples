/*
 *
 *    Copyright (c) 2022-2023 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_system.h"

#include "AppTask.h"
#include "Button.h"
#include <lib/support/CodeUtils.h>
#include <platform/CHIPDeviceLayer.h>
#include <vector>

static const char TAG[] = "Button";

Button::Button() {}

static void btn_task_cb(void *pvParameters)
{
    uint32_t press_start_time = 0, press_duration = 0;
    uint8_t btn_pressed = 0, cur_state = 0, last_state = 1;
    
    while (1) {
        cur_state = gpio_get_level((gpio_num_t)CONFIG_BUTTON_GPIO_NUM);

        if (1 == last_state && 0 == cur_state) { // pressed
            vTaskDelay(pdMS_TO_TICKS(CONFIG_DEBOUNCE_MS));
            if (0 == gpio_get_level((gpio_num_t)CONFIG_BUTTON_GPIO_NUM)) {
                press_start_time = xTaskGetTickCount();
                btn_pressed = 1;
            }
        }

        if (0 == last_state && 1 == cur_state && btn_pressed) { // released
            vTaskDelay(pdMS_TO_TICKS(CONFIG_DEBOUNCE_MS));
            if (1 == gpio_get_level((gpio_num_t)CONFIG_BUTTON_GPIO_NUM)) {
                press_duration = xTaskGetTickCount() - press_start_time;
                if (press_duration < pdMS_TO_TICKS(CONFIG_LONGPRESS_MS)) {
                    GetAppTask().HandleBtnPressedEvent();
                }
                btn_pressed = 0;
            }
        }
        
        if (btn_pressed && (xTaskGetTickCount() - press_start_time) >= pdMS_TO_TICKS(CONFIG_LONGPRESS_MS)) { // long pressed
            GetAppTask().HandleBtnLongPressedEvent();
            btn_pressed = 0;
        }
        
        last_state = cur_state;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

esp_err_t Button::Init()
{
    gpio_config_t io_conf = {};

    io_conf.intr_type = GPIO_INTR_DISABLE;
    io_conf.pin_bit_mask = 1ULL << CONFIG_BUTTON_GPIO_NUM;
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;

    gpio_config(&io_conf);

    xTaskCreate(btn_task_cb, "btn_task", 2048, NULL, 3, NULL);

    return ESP_OK;
}
