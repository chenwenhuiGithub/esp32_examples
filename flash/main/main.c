#include <string.h>
#include "esp_partition.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "flash";

void app_main(void) {
    /*
    #  Name,        Type, SubType, Offset,   Size
    *  reserve                     0,        0x1000,
    *  bootloader                  0x1000,   0x7000(28K),
    *  par_table                   0x8000,   0x1000, 
    *  nvs,         data, nvs,     0x9000,   0x6000(24K),
    *  otadata,     data, ota,     0xf000,   0x2000,
    *  phy_init,    data, phy,     0x11000,  0x1000,
    *  ota_0,       app,  ota_0,   0x20000,  0x1a9000(1700K),
    *  ota_1,       app,  ota_1,   0x1d0000, 0x1a9000(1700K),
    *  my_cfg,      data, 0xff,    0x379000, 0x2000,
    *  reserve,                    0x37b000, 0x85000(532K)
    */
    const esp_partition_t *partition = NULL;
    uint8_t write_buf[] = "Hello world, my name is esp32";
    uint8_t read_buf[128] = {0};

    partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "my_cfg");
    if (!partition) {
        ESP_LOGE(TAG, "not found partition");
        return;
    }
    ESP_LOGI(TAG, "partition info, addr:0x%lx size:0x%lx erase_size:0x%lx", partition->address, partition->size, partition->erase_size);

    ESP_LOGI(TAG, "read init");
    memset(read_buf, 0, sizeof(read_buf));
    esp_partition_read(partition, 0, read_buf, sizeof(read_buf));
    ESP_LOG_BUFFER_HEX(TAG, read_buf, sizeof(read_buf));

    ESP_LOGI(TAG, "read after write");
    esp_partition_write(partition, 0, write_buf, sizeof(write_buf));
    memset(read_buf, 0, sizeof(read_buf));
    esp_partition_read(partition, 0, read_buf, sizeof(read_buf));
    ESP_LOGI(TAG, "%s", read_buf);

    ESP_LOGI(TAG, "read after erase");
    esp_partition_erase_range(partition, 0, 0x1000); // offset:4K aligned, size:4K multiple
    memset(read_buf, 0, sizeof(read_buf));
    esp_partition_read(partition, 0, read_buf, sizeof(read_buf));
    ESP_LOG_BUFFER_HEX(TAG, read_buf, sizeof(read_buf));

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
