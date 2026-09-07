/*
 * Copyright 2025 NIBE AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @file
 * @brief Debug functions implementation
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include "esp_log.h"


static const char *TAG = "openeebus";
static char log_buf[1024] = {0};

void DebugPrintf(const char* format, ...) {
    va_list args;

    va_start(args, format);
    vsnprintf(log_buf, sizeof(log_buf) - 1, format, args);
    va_end(args);

    ESP_LOGI(TAG, "%s", log_buf);
}

void DebugHexdump(void* data, size_t data_size) {
    // ESP_LOG_BUFFER_HEXDUMP(TAG, data, data_size, ESP_LOG_INFO);
    // ESP_LOGI(TAG, "%s", (char *)data); // only WEBSOCKET_DEBUG_HEXDUMP used, log dump
}
