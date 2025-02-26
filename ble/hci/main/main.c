#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_private/periph_ctrl.h" 
#include "driver/uart.h"
#include "sdkconfig.h"


#define CONFIG_HCI_UART_PIN_RX                      16
#define CONFIG_HCI_UART_PIN_TX                      17


static const char *TAG = "ble_hci";

void app_main(void) {
    esp_err_t err = ESP_OK;
    uart_config_t uart_cfg = {
        .baud_rate = CONFIG_BTDM_CTRL_HCI_UART_BAUDRATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    // .hci_uart_no = CONFIG_BTDM_CTRL_HCI_UART_NO = UART_NUM_2
    // .hci_uart_baudrate = CONFIG_BTDM_CTRL_HCI_UART_BAUDRATE = 115200
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();                                            

    err = nvs_flash_init();
    if (ESP_ERR_NVS_NO_FREE_PAGES == err || ESP_ERR_NVS_NEW_VERSION_FOUND == err) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "nvs_flash_init error:%d", err);
        return;
    }

    periph_module_enable(PERIPH_UHCI0_MODULE);

    uart_driver_install(CONFIG_BTDM_CTRL_HCI_UART_NO, 1024, 0, 0, NULL, 0);
    uart_param_config(CONFIG_BTDM_CTRL_HCI_UART_NO, &uart_cfg);
    // UART0(RX:3, TX:1), UART2(RX:16, TX:17)
    uart_set_pin(CONFIG_BTDM_CTRL_HCI_UART_NO, CONFIG_HCI_UART_PIN_TX, CONFIG_HCI_UART_PIN_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    esp_bt_controller_init(&bt_cfg);
    esp_bt_controller_enable(ESP_BT_MODE_BLE);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
