/*
 *
 *    Copyright (c) 2021-2023 Project CHIP Authors
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

#pragma once

#include "driver/gpio.h"
#include "esp_log.h"
#include "driver/ledc.h"
#include "hal/ledc_types.h"


#define CONFIG_GPIO_RGB_R           12
#define CONFIG_GPIO_RGB_G           13
#define CONFIG_GPIO_RGB_B           14
#define CONFIG_CHANNEL_RGB_R        LEDC_CHANNEL_1
#define CONFIG_CHANNEL_RGB_G        LEDC_CHANNEL_2
#define CONFIG_CHANNEL_RGB_B        LEDC_CHANNEL_3

#define CONFIG_LEDC_MODE            LEDC_LOW_SPEED_MODE
#define CONFIG_LEDC_FREQ            4000
#define CONFIG_LEDC_DUTY_RES        LEDC_TIMER_10_BIT

#define RGB_TO_DUTY(x)              ((x) * (1 << CONFIG_LEDC_DUTY_RES) / 255)


class LEDWidget
{
public:
    void Init(void);
    void Toggle(void);

    void SetOnoff(bool onoff);
    void SetLevel(uint8_t level);
    void SetColor(uint8_t hue, uint8_t saturation);
    bool GetOnoff(void);
    uint8_t GetLevel(void);
    uint8_t GetColorHue(void);
    uint8_t GetColorSaturation(void);

private:
    bool mOnoff;
    uint8_t mLevel;
    uint8_t mHue;
    uint8_t mSaturation;

    void DoSet(void);
};
