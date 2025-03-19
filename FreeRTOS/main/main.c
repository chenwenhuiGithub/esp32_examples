#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_heap_caps.h"


#define EVENT_KEY1                              (1 << 0)
#define EVENT_KEY2                              (1 << 1)


static const char *TAG = "freertos";
static TimerHandle_t hd_timer = NULL;
static QueueHandle_t hd_queue = NULL;
static SemaphoreHandle_t hd_sem = NULL;
static SemaphoreHandle_t hd_mutex = NULL;
static EventGroupHandle_t hd_event = NULL;

static void mem_task_cb(void *pvParameters) {
    char buf[512] = {0};

    while (1) {
        vTaskList(buf);
        printf("Task summary:\n%s\n", buf);
		heap_caps_print_heap_info(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL);
        vTaskDelay(pdMS_TO_TICKS(30000));
    }
}


static void led_timer_cb(TimerHandle_t xTimer) {
    static uint8_t led_status = 0;

    if (0 == led_status) {
        led_status = 1;
        ESP_LOGI(TAG, "led on");
    } else {
        led_status = 0;
        ESP_LOGI(TAG, "led off");
    }
}


static void queue1_task_cb(void *pvParameters) {
    BaseType_t xReturn = pdTRUE;
    uint32_t recv_data = 0;

    while (1) {
        xReturn = xQueueReceive(hd_queue, &recv_data, portMAX_DELAY);
        if (pdTRUE != xReturn) {
            ESP_LOGE(TAG, "xQueueReceive failed");
        } else {
            ESP_LOGI(TAG, "xQueueReceive:%lu", recv_data);
        }
    }
}

static void queue2_task_cb(void *pvParameters) {
    BaseType_t xReturn = pdTRUE;
    static uint32_t send_data = 0;

    while (1) {
        xReturn = xQueueSend(hd_queue, &send_data, 0); // value-copy mode
        if (pdTRUE != xReturn) {
            ESP_LOGE(TAG, "xQueueSend failed");
        }
        send_data++;
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}


static void sem1_task_cb(void *pvParameters) {
    BaseType_t xReturn = pdTRUE;

    while (1) {
        xReturn = xSemaphoreTake(hd_sem, pdMS_TO_TICKS(2000));
        if (pdTRUE != xReturn) {
            ESP_LOGE(TAG, "xSemaphoreTake sem failed");
        } else {
            ESP_LOGI(TAG, "xSemaphoreTake sem success");
        }
    }
}

static void sem2_task_cb(void *pvParameters) {
    BaseType_t xReturn = pdTRUE;

    while (1) {
        xReturn = xSemaphoreGive(hd_sem);
        if (pdTRUE != xReturn) {
            ESP_LOGE(TAG, "xSemaphoreGive sem failed");
        }
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}


static void mutex1_task_cb(void *pvParameters) {
    BaseType_t xReturn = pdTRUE;

    while (1) {
        xReturn = xSemaphoreTake(hd_mutex, pdMS_TO_TICKS(2000));
        if (pdTRUE != xReturn) {
            ESP_LOGE(TAG, "xSemaphoreTake1 mutex failed");
        } else {
            ESP_LOGI(TAG, "xSemaphoreTake1 mutex success");
            xReturn = xSemaphoreGive(hd_mutex);
            if (pdTRUE != xReturn) {
                ESP_LOGE(TAG, "xSemaphoreGive1 mutex failed");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

static void mutex2_task_cb(void *pvParameters) {
    BaseType_t xReturn = pdTRUE;

    while (1) {
        xReturn = xSemaphoreTake(hd_mutex, pdMS_TO_TICKS(3000));
        if (pdTRUE != xReturn) {
            ESP_LOGE(TAG, "xSemaphoreTake2 mutex failed");
        } else {
            ESP_LOGI(TAG, "xSemaphoreTake2 mutex success");
            xReturn = xSemaphoreGive(hd_mutex);
            if (pdTRUE != xReturn) {
                ESP_LOGE(TAG, "xSemaphoreGive2 mutex failed");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}


static void event1_task_cb(void* pvParameters) {
    EventBits_t event_bits = 0;

    while (1) {
        // xClearOnExit:
        //      pdFALSE: bits in hd_event NOT cleared when xEventGroupWaitBits() return
        //      pdTRUE:  bits in hd_event cleared when xEventGroupWaitBits() return
        // xWaitForAllBits: 
        //      pdFALSE: ANYONE bit in hd_event set or timeout trigger xEventGroupWaitBits() return
        //      pdTRUE:  ALL bits in hd_event set or timeout trigger xEventGroupWaitBits() return
        event_bits = xEventGroupWaitBits(hd_event, EVENT_KEY1 | EVENT_KEY2, pdTRUE, pdTRUE, portMAX_DELAY);
        ESP_LOGI(TAG, "event_bits:0x%08X", (unsigned int)event_bits);
        if ((event_bits & EVENT_KEY1) && (event_bits & EVENT_KEY2)) {
            ESP_LOGI(TAG, "EVENT_KEY1 and EVENT_KEY2 occured");
        }
    }
}

static void event2_task_cb(void* pvParameters) {
    while (1) {
        xEventGroupSetBits(hd_event, EVENT_KEY1);
        vTaskDelay(pdMS_TO_TICKS(2000));
        xEventGroupSetBits(hd_event, EVENT_KEY2);
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}


void app_main(void) {
    BaseType_t xReturn = pdTRUE;

    // components\freertos\config\include\freertos\FreeRTOSConfig.h
    // components\freertos\config\xtensa\include\freertos\FreeRTOSConfig_arch.h
    // components\freertos\FreeRTOS-Kernel\portable\xtensa\include\freertos\portmacro.h
    xReturn = xTaskCreate(mem_task_cb, "mem_task", 4096, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate mem_task failed");
    }

    hd_timer = xTimerCreate("led_timer", pdMS_TO_TICKS(5000), pdTRUE, NULL, led_timer_cb);
    if (!hd_timer) {
        ESP_LOGE(TAG, "xTimerCreate led_timer failed");
    } else {
        xTimerStart(hd_timer, 0);
    }

    hd_queue = xQueueCreate(5, sizeof(uint32_t));
    if (!hd_queue) {
        ESP_LOGE(TAG, "xQueueCreate failed");
    }
    xReturn = xTaskCreate(queue1_task_cb, "queue1_task", 2048, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate queue1_task failed");
    }
    xReturn = xTaskCreate(queue2_task_cb, "queue2_task", 2048, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate queue2_task failed");
    }

    hd_sem = xSemaphoreCreateCounting(5, 0);
    if (!hd_sem) {
        ESP_LOGE(TAG, "xSemaphoreCreateCounting failed");
    }
    xReturn = xTaskCreate(sem1_task_cb, "sem1_task", 2048, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate sem1_task failed");
    }
    xReturn = xTaskCreate(sem2_task_cb, "sem2_task", 2048, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate sem2_task failed");
    }

    hd_mutex = xSemaphoreCreateMutex();
    if (!hd_mutex) {
        ESP_LOGE(TAG, "xSemaphoreCreateMutex failed");
    }
    xReturn = xTaskCreate(mutex1_task_cb, "mutex1_task", 2048, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate mutex1_task failed");
    }
    xReturn = xTaskCreate(mutex2_task_cb, "mutex2_task", 2048, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate mutex2_task failed");
    }

    hd_event = xEventGroupCreate();
    if (!hd_event) {
        ESP_LOGE(TAG, "xEventGroupCreate failed");
    }
    xReturn = xTaskCreate(event1_task_cb, "event1_task", 2048, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate event1_task failed");
    }
    xReturn = xTaskCreate(event2_task_cb, "event2_task", 2048, NULL, 2, NULL);
    if (pdTRUE != xReturn) {
        ESP_LOGE(TAG, "xTaskCreate event2_task failed");
    }

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
