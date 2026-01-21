/*
 *
 *    Copyright (c) 2021-2023 Project CHIP Authors
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
#include "AppTask.h"

#include "DeviceCallbacks.h"
#include "LEDWidget.h"

#include <app/util/util.h>

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/ConcreteAttributePath.h>
#include <app/server/Server.h>
#include <lib/support/logging/CHIPLogging.h>

#include <app/util/attribute-storage.h>
#include <platform/KeyValueStoreManager.h>
#include <lib/support/CodeUtils.h>
#include <platform/CHIPDeviceLayer.h>

static const char TAG[] = "DeviceCallbacks";

extern LEDWidget AppLED;

using namespace chip;
using namespace chip::Inet;
using namespace chip::System;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::DeviceLayer;

void AppDeviceCallbacks::PostAttributeChangeCallback(EndpointId endpointId, ClusterId clusterId, AttributeId attributeId,
                                                     uint8_t type, uint16_t size, uint8_t * value)
{
    ESP_LOGI(TAG, "PostAttributeChangeCallback - EndPoint ID: '0x%x', Cluster ID: '0x%" PRIx32 "', Attribute ID: '0x%" PRIx32 "'",
             endpointId, clusterId, attributeId);

    switch (clusterId)
    {
    case OnOff::Id:
        OnOnOffPostAttributeChangeCallback(endpointId, attributeId, value);
        break;

    case LevelControl::Id:
        OnLevelControlAttributeChangeCallback(endpointId, attributeId, value);
        break;

    case ColorControl::Id:
        OnColorControlAttributeChangeCallback(endpointId, attributeId, value);
        break;

    default:
        ESP_LOGI(TAG, "Unhandled cluster ID: %" PRIu32, clusterId);
        break;
    }

    ESP_LOGI(TAG, "Current free heap: %u\n", static_cast<unsigned int>(heap_caps_get_free_size(MALLOC_CAP_8BIT)));
}

void AppDeviceCallbacks::OnOnOffPostAttributeChangeCallback(EndpointId endpointId, AttributeId attributeId, uint8_t * value)
{
    VerifyOrExit(attributeId == OnOff::Attributes::OnOff::Id,
                 ESP_LOGI(TAG, "Unhandled Attribute ID: '0x%" PRIx32 "'", attributeId));
    VerifyOrExit(endpointId == 1, ESP_LOGE(TAG, "Unexpected EndPoint ID: `0x%02x'", endpointId));

    ESP_LOGI(TAG, "set onoff:%d", *value);
    AppLED.SetOnoff(*value); // false - off, true - on

exit:
    return;
}

void AppDeviceCallbacks::OnLevelControlAttributeChangeCallback(EndpointId endpointId, AttributeId attributeId, uint8_t * value)
{
    VerifyOrExit(attributeId == LevelControl::Attributes::CurrentLevel::Id,
                 ESP_LOGI(TAG, "Unhandled Attribute ID: '0x%" PRIx32 "'", attributeId));
    VerifyOrExit(endpointId == 1, ESP_LOGE(TAG, "Unexpected EndPoint ID: `0x%02x'", endpointId));

    ESP_LOGI(TAG, "set level:%d", *value);
    AppLED.SetLevel(*value); // 0 - 254

exit:
    return;
}

void AppDeviceCallbacks::OnColorControlAttributeChangeCallback(EndpointId endpointId, AttributeId attributeId, uint8_t * value)
{
    using namespace ColorControl::Attributes;

    uint8_t hue, saturation;

    VerifyOrExit(attributeId == CurrentHue::Id || attributeId == CurrentSaturation::Id,
                 ESP_LOGI(TAG, "Unhandled AttributeId ID: '0x%" PRIx32 "'", attributeId));
    VerifyOrExit(endpointId == 1, ESP_LOGE(TAG, "Unexpected EndPoint ID: `0x%02x'", endpointId));

    if (attributeId == CurrentHue::Id)
    {
        hue = *value; // 0 - 254
        CurrentSaturation::Get(endpointId, &saturation);
    }
    else
    {
        saturation = *value; // 0 - 254
        CurrentHue::Get(endpointId, &hue);
    }
    ESP_LOGI(TAG, "set hue:%d, saturation:%d", hue, saturation);
    AppLED.SetColor(hue, saturation);

exit:
    return;
}

/** @brief OnOff Cluster Init
 *
 * This function is called when a specific cluster is initialized. It gives the
 * application an opportunity to take care of cluster initialization procedures.
 * It is called exactly once for each endpoint where cluster is present.
 *
 * @param endpoint   Ver.: always
 *
 * emberAfOnOffClusterInitCallback happens before the stack initialize the cluster
 * attributes to the default value.
 * The logic here expects something similar to the deprecated Plugins callback
 * emberAfPluginOnOffClusterServerPostInitCallback.
 *
 */
void emberAfOnOffClusterInitCallback(EndpointId endpoint)
{
    bool onoff = false;

    ESP_LOGI(TAG, "emberAfOnOffClusterInitCallback, ep:%d", endpoint);

    if (1 == endpoint) {
        if (Protocols::InteractionModel::Status::Success == Clusters::OnOff::Attributes::OnOff::Get(1, &onoff)) {
            AppLED.SetOnoff(onoff);
        }
    }
}

void emberAfLevelControlClusterInitCallback(EndpointId endpoint)
{
    DataModel::Nullable<uint8_t> level;

    ESP_LOGI(TAG, "emberAfLevelControlClusterInitCallback, ep:%d", endpoint);

    if (1 == endpoint) {
        if (Protocols::InteractionModel::Status::Success == Clusters::LevelControl::Attributes::CurrentLevel::Get(1, level)) {
            if (!level.IsNull()) {
                AppLED.SetLevel(level.Value());
            }
        }
    }
}

void emberAfColorControlClusterInitCallback(EndpointId endpoint)
{
    uint8_t hue = 0, saturation = 0;

    ESP_LOGI(TAG, "emberAfColorControlClusterInitCallback, ep:%d", endpoint);
    Protocols::InteractionModel::Status status = Protocols::InteractionModel::Status::Success;

    if (1 == endpoint) {
        if (Protocols::InteractionModel::Status::Success == Clusters::ColorControl::Attributes::CurrentHue::Get(1, &hue) &&
            Protocols::InteractionModel::Status::Success == Clusters::ColorControl::Attributes::CurrentSaturation::Get(1, &saturation)) {
            AppLED.SetColor(hue, saturation);
        }
    }
}


void AppDeviceCallbacksDelegate::OnIPv4ConnectivityEstablished()
{
    ESP_LOGI(TAG, "OnIPv4ConnectivityEstablished");
}

void AppDeviceCallbacksDelegate::OnIPv4ConnectivityLost()
{
    ESP_LOGI(TAG, "OnIPv4ConnectivityLost");
}
