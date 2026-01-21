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

#include "AppTask.h"
#include "Button.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app/server/Server.h>

#define APP_TASK_NAME "APP"
#define APP_EVENT_QUEUE_SIZE 10
#define APP_TASK_STACK_SIZE (3072)

using namespace ::chip;
using namespace ::chip::app;
using namespace ::chip::DeviceLayer;

static const char TAG[] = "APPTask";

LEDWidget AppLED;
Button AppButton;

namespace {
QueueHandle_t sAppEventQueue;
TaskHandle_t sAppTaskHandle;
} // namespace

AppTask AppTask::sAppTask;

CHIP_ERROR AppTask::StartAppTask()
{
    sAppEventQueue = xQueueCreate(APP_EVENT_QUEUE_SIZE, sizeof(AppEvent));
    if (sAppEventQueue == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate app event queue");
        return APP_ERROR_EVENT_QUEUE_FAILED;
    }

    BaseType_t xReturned;
    xReturned = xTaskCreate(AppTaskMain, APP_TASK_NAME, APP_TASK_STACK_SIZE, NULL, 1, &sAppTaskHandle);
    return (xReturned == pdPASS) ? CHIP_NO_ERROR : APP_ERROR_CREATE_TASK_FAILED;
}

void AppTask::AppTaskMain(void * pvParameter)
{
    AppEvent event;

    AppButton.Init();
    AppLED.Init();
    ESP_LOGI(TAG, "App Task started");

    while (true)
    {
        BaseType_t eventReceived = xQueueReceive(sAppEventQueue, &event, pdMS_TO_TICKS(10));
        while (eventReceived == pdTRUE)
        {
            if (event.mHandler)
            {
                event.mHandler(&event);
            }
            eventReceived = xQueueReceive(sAppEventQueue, &event, 0); // return immediately if the queue is empty
        }
    }
}

void AppTask::HandleBtnPressedEvent()
{
    AppEvent btn_event = {};
    btn_event.Type     = AppEvent::kEventType_Btn_Pressed;
    btn_event.mHandler = AppTask::BtnPressedEventHandler;
    xQueueSend(sAppEventQueue, &btn_event, 1);
}

void AppTask::HandleBtnLongPressedEvent()
{
    AppEvent btn_event = {};
    btn_event.Type     = AppEvent::kEventType_Btn_LongPressed;
    btn_event.mHandler = AppTask::BtnLongPressedEventHandler;
    xQueueSend(sAppEventQueue, &btn_event, 1);
}

void AppTask::BtnPressedEventHandler(AppEvent * aEvent)
{
    ESP_LOGI(TAG, "btn pressed");

    AppLED.Toggle();
    chip::DeviceLayer::PlatformMgr().LockChipStack();
    sAppTask.UpdateOnOffClusterState();
    chip::DeviceLayer::PlatformMgr().UnlockChipStack();
}

void AppTask::BtnLongPressedEventHandler(AppEvent * aEvent)
{
    ESP_LOGI(TAG, "btn long pressed");

    chip::Server::GetInstance().ScheduleFactoryReset();
}

// zzz_generated/app-common/app-common/zap-generated/attributes/Accessors.cpp
// Clusters::LevelControl::Attributes::CurrentLevel::Set(1, value);
//      emberAfWriteAttribute(endpoint, Clusters::LevelControl::Id, Clusters::LevelControl::Attributes::CurrentLevel::Id, dataPtr, ZCL_INT8U_ATTRIBUTE_TYPE);
//          emAfWriteAttribute(path, completeInput, true);
//              emAfReadOrWriteAttribute(&record, &metadata, nullptr, 0, false); // read attribute metadata from DB
//              MatterPreAttributeChangeCallback(attributePath, input.dataType, emberAfAttributeSize(metadata), input.dataPtr);
//              emAfClusterPreAttributeChangedCallback(attributePath, input.dataType, emberAfAttributeSize(metadata), input.dataPtr);
//              emAfReadOrWriteAttribute(&record, nullptr, input.dataPtr, 0, true); // write attribute metadata to DB
//              emAfSaveAttributeToStorageIfNeeded(input.dataPtr, path.mEndpointId, path.mClusterId, metadata); // write attribute value to nvs flash
//                  GetAttributePersistenceProvider()->WriteValue(ConcreteAttributePath(endpoint, clusterId, metadata->attributeId), ByteSpan(data, dataSize));
//              MatterPostAttributeChangeCallback(attributePath, input.dataType, emberAfAttributeSize(metadata), input.dataPtr);
//              emAfClusterAttributeChangedCallback(attributePath);
// Clusters::LevelControl::Attributes::CurrentLevel::Get(1, value);
//      emberAfReadAttribute(endpoint, Clusters::LevelControl::Id, Clusters::LevelControl::Attributes::CurrentLevel::Id, dataPtr, sizeof(data));
//          emAfReadOrWriteAttribute(&record, &metadata, dataPtr, readLength, false); // read attribute metadata from DB

void AppTask::UpdateOnOffClusterState()
{
    uint8_t value = AppLED.GetOnoff();

    ESP_LOGI(TAG, "Writing value:%d to OnOff cluster", value);

    Protocols::InteractionModel::Status status = Clusters::OnOff::Attributes::OnOff::Set(1, value);
    if (status != Protocols::InteractionModel::Status::Success)
    {
        ESP_LOGE(TAG, "Updating OnOff cluster failed: %x", to_underlying(status));
    }
}

void AppTask::UpdateLevelControlClusterState()
{
    uint8_t value = AppLED.GetLevel();

    ESP_LOGI(TAG, "Writing value:%d to LevelControl cluster", value);

    Protocols::InteractionModel::Status status = Clusters::LevelControl::Attributes::CurrentLevel::Set(1, value);
    if (status != Protocols::InteractionModel::Status::Success)
    {
        ESP_LOGE(TAG, "Updating LevelControl failed: %x", to_underlying(status));
    }
}

void AppTask::UpdateColorControlClusterState()
{
    uint8_t value_h = AppLED.GetColorHue();
    uint8_t value_s = AppLED.GetColorSaturation();

    ESP_LOGI(TAG, "Writing value:%d,%d to ColorControl cluster", value_h, value_s);

    Protocols::InteractionModel::Status status = Protocols::InteractionModel::Status::Success;
    status = Clusters::ColorControl::Attributes::CurrentHue::Set(1, value_h);
    status = Clusters::ColorControl::Attributes::CurrentSaturation::Set(1, value_s);
    if (status != Protocols::InteractionModel::Status::Success)
    {
        ESP_LOGE(TAG, "Updating ColorControl cluster failed: %x", to_underlying(status));
    }
}
