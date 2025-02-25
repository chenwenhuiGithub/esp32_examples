#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#define CONFIG_NVS_NAMESPACE                "wenhui_ns"


static const char *TAG = "nvs";
static nvs_handle_t hd_nvs = 0;

void app_main(void) {
    esp_err_t err = ESP_OK;
    const char* k_restart = "restart";
    uint32_t v_restart = 0;
    const char* k_username = "username";
    const char* k_password = "password";
    char v_username[16] = {0};
    uint8_t v_password[8] = {0};
    size_t required_size = 0;
    uint32_t i = 0;

    err = nvs_flash_init();
    if (ESP_ERR_NVS_NO_FREE_PAGES == err || ESP_ERR_NVS_NEW_VERSION_FOUND == err) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "nvs_flash_init error:%d", err);
        return;
    }

    err = nvs_open(CONFIG_NVS_NAMESPACE, NVS_READWRITE, &hd_nvs);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "nvs_open error:%d", err);
        return;
    }

    err = nvs_get_u32(hd_nvs, k_restart, &v_restart);
    if (ESP_OK != err) {
        if (ESP_ERR_NVS_NOT_FOUND == err) { // why don't return ESP_ERR_NVS_NOT_FOUND?
            ESP_LOGI(TAG, "kv not set:%s", k_restart);
        } else {
            ESP_LOGE(TAG, "kv get error, key:%s error:%d", k_restart, err);
        }
        v_restart = 0;
    } else {
        ESP_LOGI(TAG, "%s:%lu", k_restart, v_restart);
        v_restart++;
    }
    err = nvs_set_u32(hd_nvs, k_restart, v_restart);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "kv set error, key:%s error:%d", k_restart, err);
    }

    err = nvs_get_str(hd_nvs, k_username, NULL, &required_size);
    if (ESP_OK != err) {
        if (ESP_ERR_NVS_NOT_FOUND == err) {
            ESP_LOGI(TAG, "kv not set:%s", k_username);
        } else {
            ESP_LOGE(TAG, "kv get error, key:%s error:%d", k_username, err);
        }
        strncpy(v_username, "admin", strlen("admin"));
        err = nvs_set_str(hd_nvs, k_username, v_username);
        if (ESP_OK != err) {
            ESP_LOGE(TAG, "kv set error, key:%s error:%d", k_username, err);
        }
    } else {
        nvs_get_str(hd_nvs, k_username, v_username, &required_size);
        ESP_LOGI(TAG, "%s:%s", k_username, v_username);
    }

    err = nvs_get_blob(hd_nvs, k_password, NULL, &required_size);
    if (ESP_OK != err) {
        if (ESP_ERR_NVS_NOT_FOUND == err) {
            ESP_LOGI(TAG, "kv not set:%s", k_password);
        } else {
            ESP_LOGE(TAG, "kv get error, key:%s error:%d", k_password, err);
        }
        for (i = 0; i < sizeof(v_password); i++) {
            v_password[i] = i;
        }
    } else {
        nvs_get_blob(hd_nvs, k_password, v_password, &required_size);
        ESP_LOGI(TAG, "%s:%02x %02x %02x %02x %02x %02x %02x %02x",
                 k_password, v_password[0], v_password[1], v_password[2], v_password[3], v_password[4], v_password[5], v_password[6], v_password[7]);
        for (i = 0; i < sizeof(v_password); i++) {
            v_password[i]++;
        }   
    }
    err = nvs_set_blob(hd_nvs, k_password, v_password, sizeof(v_password));
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "kv set error, key:%s error:%d", k_password, err);
    }

    nvs_commit(hd_nvs);
    nvs_close(hd_nvs);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
