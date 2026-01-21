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

#include "LEDWidget.h"
#include "ColorFormat.h"

#include <app/util/attribute-storage.h>
#include <platform/KeyValueStoreManager.h>
#include <lib/support/CodeUtils.h>
#include <platform/CHIPDeviceLayer.h>

using namespace chip;
using namespace chip::DeviceLayer;

static const char TAG[] = "LED";

void LEDWidget::Init(void)
{
    mOnoff      = false;
    mLevel      = 0;
    mHue        = 0;
    mSaturation = 0;

    ledc_timer_config_t ledc_timer_cfg = {
        .speed_mode             = CONFIG_LEDC_MODE,
        .duty_resolution        = CONFIG_LEDC_DUTY_RES,
        .timer_num              = LEDC_TIMER_0,
        .freq_hz                = CONFIG_LEDC_FREQ,
        .clk_cfg                = LEDC_AUTO_CLK
    };
    ledc_channel_config_t ledc_channel_cfg = {
        .gpio_num               = CONFIG_GPIO_RGB_R,
        .speed_mode             = CONFIG_LEDC_MODE,
        .channel                = CONFIG_CHANNEL_RGB_R,
        .intr_type              = LEDC_INTR_DISABLE,
        .timer_sel              = LEDC_TIMER_0,
        .duty                   = 0,
        .hpoint                 = 0,
        .flags                  = {
            .output_invert = 0
        }
    };

    ledc_timer_config(&ledc_timer_cfg);
    ledc_channel_config(&ledc_channel_cfg);
    ledc_channel_cfg.gpio_num = CONFIG_GPIO_RGB_G;
    ledc_channel_cfg.channel  = CONFIG_CHANNEL_RGB_G;
    ledc_channel_config(&ledc_channel_cfg);
    ledc_channel_cfg.gpio_num = CONFIG_GPIO_RGB_B;
    ledc_channel_cfg.channel  = CONFIG_CHANNEL_RGB_B;
    ledc_channel_config(&ledc_channel_cfg);
}

void LEDWidget::SetOnoff(bool onoff)
{
    ESP_LOGI(TAG, "Setting onoff, %d -> %d", mOnoff, onoff ? 1 : 0);
    if (onoff == mOnoff)
        return;

    mOnoff = onoff;

    DoSet();
}

void LEDWidget::Toggle()
{
    ESP_LOGI(TAG, "Toggling onoff, %d -> %d", mOnoff, !mOnoff);
    mOnoff = !mOnoff;

    DoSet();
}

void LEDWidget::SetLevel(uint8_t level)
{
    ESP_LOGI(TAG, "Setting level, %d -> %d", mLevel, level);
    if (level == mLevel)
        return;

    mLevel = level;

    DoSet();
}

void LEDWidget::SetColor(uint8_t hue, uint8_t saturation)
{
    ESP_LOGI(TAG, "Setting color, %d,%d -> %d,%d", mHue, mSaturation, hue, saturation);
    if (hue == mHue && saturation == mSaturation)
        return;

    mHue        = hue;
    mSaturation = saturation;

    DoSet();
}

uint8_t LEDWidget::GetLevel()
{
    return this->mLevel;
}

bool LEDWidget::GetOnoff()
{
    return this->mOnoff;
}

uint8_t LEDWidget::GetColorHue()
{
    return this->mHue;
}

uint8_t LEDWidget::GetColorSaturation()
{
    return this->mSaturation;
}

void LEDWidget::DoSet(void)
{
    uint8_t level = mOnoff ? mLevel : 0;

    HsvColor_t hsv = { mHue, mSaturation, level };
    RgbColor_t rgb = HsvToRgb(hsv);

    ledc_set_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_R, RGB_TO_DUTY(rgb.r));
    ledc_set_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_G, RGB_TO_DUTY(rgb.g));
    ledc_set_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_B, RGB_TO_DUTY(rgb.b));
    ledc_update_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_R);
    ledc_update_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_G);
    ledc_update_duty(CONFIG_LEDC_MODE, CONFIG_CHANNEL_RGB_B);
}
