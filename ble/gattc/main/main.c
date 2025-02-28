#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_mac.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"


#define CONFIG_GATTC_APP_ID                                 0x5AA5
#define CONFIG_GATTC_ADV_SVC                                0x00FF
#define CONFIG_GATTC_UUID_SVC_TEST                          0x18FF
#define CONFIG_GATTC_UUID_CHAR_RX                           0x2AFE
#define CONFIG_GATTC_UUID_CHAR_TX                           0x2AFF

/*
att_handle(2B)  att_type(UUID, 2B/16B)                      att_value(0-512B)                           att_permission
// service battery
0x0038          0x2800(PRIMARY_SERVICE)                     0x180F(SERVICE_BATTERY)                     PERMISSION_READ
0x0039          0x2803(CHARACTERISTIC_DECLARATION)          0x02(CHARACTERISTIC_PROPERITY_READ)         PERMISSION_READ
                                                            0x003A(handle)
                                                            0x2A19(CHARACTERISTIC_LEVEL)
0x003A          0x2A19(CHARACTERISTIC_LEVEL)                [1B]0x19                                    PERMISSION_READ

// service test
0x003B          0x2800(PRIMARY_SERVICE)                     0x18FF(SERVICE_TEST)                        PERMISSION_READ
0x003C          0x2803(CHARACTERISTIC_DECLARATION)          0x04(CHARACTERISTIC_PROPERITY_WRITE_NR)     PERMISSION_READ
                                                            0x003D(handle)
                                                            0x2AFE(CHARACTERISTIC_RX)
0x003D          0x2AFE(CHARACTERISTIC_RX)                   [1024B]                                     PERMISSION_WRITE
0x003E          0x2803(CHARACTERISTIC_DECLARATION)          0x10(CHARACTERISTIC_PROPERITY_NOTIFY)       PERMISSION_READ
                                                            0x003F(handle)
                                                            0x2AFF(CHARACTERISTIC_TX)
0x003F          0x2AFF(CHARACTERISTIC_TX)                   [1024B]                                     PERMISSION_READ
0x0040          0x2902(CHARACTERISTIC_DESCRIPTOR_CCC)       [2B]0x0001                                  PERMISSION_READ|WRITE
*/

static const char *TAG = "ble_gattc";
static esp_gatt_if_t g_gatt_if = 0;
static uint8_t remote_addr[ESP_BD_ADDR_LEN] = {0};
static uint8_t during_scan = 1;
static esp_ble_scan_params_t scan_params = {
    .scan_type          = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval      = 0x50,
    .scan_window        = 0x30,
    .scan_duplicate     = BLE_SCAN_DUPLICATE_ENABLE // filter out duplicate adv report
};
static esp_ble_gatt_creat_conn_params_t conn_params = {0};

static esp_bt_uuid_t uuid_svc_bat = {
    .len = ESP_UUID_LEN_16,
    .uuid = {.uuid16 = ESP_GATT_UUID_BATTERY_SERVICE_SVC}
};
static esp_bt_uuid_t uuid_svc_test = {
    .len = ESP_UUID_LEN_16,
    .uuid = {.uuid16 = CONFIG_GATTC_UUID_SVC_TEST}
};
static esp_bt_uuid_t uuid_char_level = {
    .len = ESP_UUID_LEN_16,
    .uuid = {.uuid16 = ESP_GATT_UUID_BATTERY_LEVEL}
};
static esp_bt_uuid_t uuid_char_rx = {
    .len = ESP_UUID_LEN_16,
    .uuid = {.uuid16 = CONFIG_GATTC_UUID_CHAR_RX}
};
static esp_bt_uuid_t uuid_char_tx = {
    .len = ESP_UUID_LEN_16,
    .uuid = {.uuid16 = CONFIG_GATTC_UUID_CHAR_TX}
};
static esp_bt_uuid_t uuid_desc_tx_ccc = {
    .len = ESP_UUID_LEN_16,
    .uuid = {.uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG}
};
static esp_gattc_service_elem_t svc_elem_bat = {0};
static esp_gattc_service_elem_t svc_elem_test = {0};
static esp_gattc_char_elem_t char_elem_level = {0};
static esp_gattc_char_elem_t char_elem_rx = {0};
static esp_gattc_char_elem_t char_elem_tx = {0};
static esp_gattc_descr_elem_t desc_elem_tx_ccc = {0};

static void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    char adv_format[128] = {0};
    uint32_t adv_format_len = 0, i = 0;
    uint8_t *adv_svc = NULL;
    uint8_t adv_svc_len = 0;    

    switch (event) {
    case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT, status:0x%04X", param->scan_param_cmpl.status);
        break;
    case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_SCAN_START_COMPLETE_EVT, status:0x%04X", param->scan_start_cmpl.status);
        break;
    case ESP_GAP_BLE_SCAN_RESULT_EVT:
        if (during_scan) {
            ESP_LOGI(TAG, "ESP_GAP_BLE_SCAN_RESULT_EVT, addr:"MACSTR" addr_type:0x%02X dev_type:0x%02X adv_type:0x%02X rssi:%d adv_len:%u scan_rsp_len:%u",
                MAC2STR(param->scan_rst.bda), param->scan_rst.ble_addr_type, param->scan_rst.dev_type, param->scan_rst.ble_evt_type,
                param->scan_rst.rssi, param->scan_rst.adv_data_len, param->scan_rst.scan_rsp_len);
            if ((0 < param->scan_rst.adv_data_len) && (param->scan_rst.adv_data_len <= ESP_BLE_ADV_DATA_LEN_MAX)) {
                adv_format_len = 0;
                for (i = 0; i < param->scan_rst.adv_data_len; i++) {
                    adv_format_len += sprintf(adv_format + adv_format_len, "%02X ", param->scan_rst.ble_adv[i]);
                }
                adv_format[adv_format_len] = '\0';
                ESP_LOGI(TAG, "%s", adv_format);
            }
            if ((0 < param->scan_rst.scan_rsp_len) && (param->scan_rst.scan_rsp_len < ESP_BLE_SCAN_RSP_DATA_LEN_MAX)) {
                adv_format_len = 0;
                for (i = 0; i < param->scan_rst.scan_rsp_len; i++) {
                    adv_format_len += sprintf(adv_format + adv_format_len, "%02X ", param->scan_rst.ble_adv[param->scan_rst.adv_data_len + i]);
                }
                adv_format[adv_format_len] = '\0';
                ESP_LOGI(TAG, "%s", adv_format);
            }

            adv_svc = esp_ble_resolve_adv_data_by_type(
                param->scan_rst.ble_adv, param->scan_rst.adv_data_len + param->scan_rst.scan_rsp_len, ESP_BLE_AD_TYPE_16SRV_CMPL, &adv_svc_len);
            if (adv_svc) {
                if (CONFIG_GATTC_ADV_SVC == (adv_svc[1] << 8 | adv_svc[0])) {
                    ESP_LOGI(TAG, "found device, stop scan, start connect");
                    during_scan = 0;
                    esp_ble_gap_stop_scanning();

                    memcpy(&conn_params.remote_bda, param->scan_rst.bda, ESP_BD_ADDR_LEN);
                    conn_params.remote_addr_type = param->scan_rst.ble_addr_type;
                    conn_params.own_addr_type = BLE_ADDR_TYPE_PUBLIC;
                    conn_params.is_direct = true;
                    conn_params.is_aux = false;
                    conn_params.phy_mask = 0x00;
                    esp_ble_gattc_enh_open(g_gatt_if, &conn_params);
                }
            }
        }
        break;
    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT, status:0x%04X", param->scan_stop_cmpl.status);
        break;
    case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT, status:0x%04X addr:"MACSTR" interval:%u latency:%u, timeout:%u",
            param->update_conn_params.status, MAC2STR(param->update_conn_params.bda),
            param->update_conn_params.conn_int, param->update_conn_params.latency, param->update_conn_params.timeout);
        break;
    case ESP_GAP_BLE_SET_PKT_LENGTH_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_SET_PKT_LENGTH_COMPLETE_EVT, status:0x%04X rx_len:%u tx_len:%u",
            param->pkt_data_length_cmpl.status, param->pkt_data_length_cmpl.params.rx_len, param->pkt_data_length_cmpl.params.tx_len);
        break;
    default:
        ESP_LOGW(TAG, "unknown GAP event:%u", event);
        break;
    }
}

static void gattc_cb(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t *param) {
    uint16_t conn_id = 0, svc_count = 0, char_count = 0, desc_count = 0;
    uint16_t notify_enable = 0x0001; // bit0 - notify, bit1 - indication
    char *write_data = "hello world", *prep_write_data1 = "hi, ", *prep_write_data2 = "shijie ", *prep_write_data3 = "nihao";
    static uint8_t prep_write_cnt = 0;

    switch (event) {
    case ESP_GATTC_REG_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_REG_EVT, status:0x%02X app_id:0x%04X", param->reg.status, param->reg.app_id);
        g_gatt_if = gattc_if;
        esp_ble_gap_set_scan_params(&scan_params);
        esp_ble_gap_start_scanning(10); // 10s
        break;
    case ESP_GATTC_OPEN_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_OPEN_EVT, status:0x%02X addr:"MACSTR" conn_id:0x%04X mtu:%u",
            param->open.status, MAC2STR(param->open.remote_bda), param->open.conn_id, param->open.mtu);
        break;
    case ESP_GATTC_CONNECT_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_CONNECT_EVT, conn_id:0x%04X role(0-master,1-slave):0x%02X addr:"MACSTR" addr_type:0x%02X interval:%u latency:%u timeout:%u",
            param->connect.conn_id, param->connect.link_role, MAC2STR(param->connect.remote_bda), param->connect.ble_addr_type,
            param->connect.conn_params.interval, param->connect.conn_params.latency, param->connect.conn_params.timeout);
        esp_ble_gattc_send_mtu_req(gattc_if, param->connect.conn_id);
        memcpy(remote_addr, param->connect.remote_bda, ESP_BD_ADDR_LEN);
        break;
    case ESP_GATTC_DISCONNECT_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_DISCONNECT_EVT, conn_id:0x%04X addr:"MACSTR" reason:0x%04X",
            param->disconnect.conn_id, MAC2STR(param->disconnect.remote_bda), param->disconnect.reason);
        break;
    case ESP_GATTC_CFG_MTU_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_CFG_MTU_EVT, status:0x%02X conn_id:0x%04X mtu:%u", param->cfg_mtu.status, param->cfg_mtu.conn_id, param->cfg_mtu.mtu);
        break;
    case ESP_GATTC_DIS_SRVC_CMPL_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_DIS_SRVC_CMPL_EVT, status:0x%02X conn_id:0x%04X", param->dis_srvc_cmpl.status, param->dis_srvc_cmpl.conn_id);
        conn_id = param->dis_srvc_cmpl.conn_id;

        svc_count = 1;
        esp_ble_gattc_get_service(gattc_if, conn_id, &uuid_svc_bat, &svc_elem_bat, &svc_count, 0);
        if (svc_count) {
            ESP_LOGI(TAG, "svc battery found, is_primary:%u start_handle:0x%04X end_handle:0x%04X uuid:0x%04X",
                svc_elem_bat.is_primary, svc_elem_bat.start_handle, svc_elem_bat.end_handle, svc_elem_bat.uuid.uuid.uuid16);
            char_count = 1;
            esp_ble_gattc_get_char_by_uuid(gattc_if, conn_id, svc_elem_bat.start_handle, svc_elem_bat.end_handle, uuid_char_level, &char_elem_level, &char_count);
            if (char_count) {
                ESP_LOGI(TAG, "char level found, handle:0x%04X property:0x%02X uuid:0x%04X",
                    char_elem_level.char_handle, char_elem_level.properties, char_elem_level.uuid.uuid.uuid16);
                if (char_elem_level.properties & ESP_GATT_CHAR_PROP_BIT_READ) {
                    esp_ble_gattc_read_char(gattc_if, conn_id, char_elem_level.char_handle, ESP_GATT_AUTH_REQ_NONE); // trigger ESP_GATTC_READ_CHAR_EVT
                } else {
                    ESP_LOGE(TAG, "char level not allow read");
                }
            } else {
                ESP_LOGE(TAG, "char level not found");
            }
        } else {
            ESP_LOGE(TAG, "svc battery not found");
        }

        svc_count = 1;
        esp_ble_gattc_get_service(gattc_if, conn_id, &uuid_svc_test, &svc_elem_test, &svc_count, 0);
        if (svc_count) {
            ESP_LOGI(TAG, "svc test found, is_primary:%u start_handle:0x%04X end_handle:0x%04X uuid:0x%04X",
                svc_elem_test.is_primary, svc_elem_test.start_handle, svc_elem_test.end_handle, svc_elem_test.uuid.uuid.uuid16);
            char_count = 1;
            esp_ble_gattc_get_char_by_uuid(gattc_if, conn_id, svc_elem_test.start_handle, svc_elem_test.end_handle, uuid_char_rx, &char_elem_rx, &char_count);
            if (char_count) {
                ESP_LOGI(TAG, "char rx found, handle:0x%04X property:0x%02X uuid:0x%04X",
                    char_elem_rx.char_handle, char_elem_rx.properties, char_elem_rx.uuid.uuid.uuid16);
                if (char_elem_rx.properties & ESP_GATT_CHAR_PROP_BIT_WRITE_NR) {
                    esp_ble_gattc_write_char(gattc_if, conn_id, char_elem_rx.char_handle,
                        strlen(write_data), (uint8_t *)write_data, ESP_GATT_WRITE_TYPE_NO_RSP, ESP_GATT_AUTH_REQ_NONE);
                } else {
                    ESP_LOGE(TAG, "char rx not allow write");
                }
            } else {
                ESP_LOGE(TAG, "char rx not found");
            }

            char_count = 1;
            esp_ble_gattc_get_char_by_uuid(gattc_if, conn_id, svc_elem_test.start_handle, svc_elem_test.end_handle, uuid_char_tx, &char_elem_tx, &char_count);
            if (char_count) {
                ESP_LOGI(TAG, "char tx found, handle:0x%04X property:0x%02X uuid:0x%04X",
                    char_elem_tx.char_handle, char_elem_tx.properties, char_elem_tx.uuid.uuid.uuid16);
                desc_count = 1;
                esp_ble_gattc_get_descr_by_char_handle(gattc_if, conn_id, char_elem_tx.char_handle, uuid_desc_tx_ccc, &desc_elem_tx_ccc, &desc_count);
                if (desc_count) {
                    ESP_LOGI(TAG, "desc tx_ccc found, handle:0x%04X uuid:0x%04X", desc_elem_tx_ccc.handle, desc_elem_tx_ccc.uuid.uuid.uuid16);
                    esp_ble_gattc_write_char_descr(gattc_if, conn_id, desc_elem_tx_ccc.handle,
                        sizeof(notify_enable), (uint8_t *)&notify_enable, ESP_GATT_WRITE_TYPE_NO_RSP, ESP_GATT_AUTH_REQ_NONE);
                    esp_ble_gattc_read_char_descr(gattc_if, conn_id, desc_elem_tx_ccc.handle, ESP_GATT_AUTH_REQ_NONE); // trigger ESP_GATTC_READ_DESCR_EVT
                    esp_ble_gattc_register_for_notify(gattc_if, remote_addr, char_elem_tx.char_handle);
                } else {
                    ESP_LOGE(TAG, "desc tx_ccc not found");
                }
            } else {
                ESP_LOGE(TAG, "char tx not found");
            }
        } else {
            ESP_LOGE(TAG, "svc test not found");
        }
        break;
    case ESP_GATTC_READ_CHAR_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_READ_CHAR_EVT, status:0x%02X conn_id:0x%04X handle:0x%04X", param->read.status, param->read.conn_id, param->read.handle);
        ESP_LOG_BUFFER_HEX(TAG, param->read.value, param->read.value_len);
        if ((char_elem_level.char_handle == param->read.handle) && (1 == param->read.value_len)) {
            ESP_LOGI(TAG, "char level:%u%%", param->read.value[0]);
        }
        break;
    case ESP_GATTC_READ_DESCR_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_READ_DESCR_EVT, status:0x%02X conn_id:0x%04X handle:0x%04X", param->read.status, param->read.conn_id, param->read.handle);
        ESP_LOG_BUFFER_HEX(TAG, param->read.value, param->read.value_len);
        if ((desc_elem_tx_ccc.handle == param->read.handle) && (2 == param->read.value_len)) {
            ESP_LOGI(TAG, "desc tx_ccc:0x%02X%02X", param->read.value[1], param->read.value[0]);
        }
        break;
    case ESP_GATTC_REG_FOR_NOTIFY_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_REG_FOR_NOTIFY_EVT, status:0x%02X handle:0x%04X", param->reg_for_notify.status, param->reg_for_notify.handle);
        break;
    case ESP_GATTC_NOTIFY_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_NOTIFY_EVT, conn_id:0x%04X addr:"MACSTR" handle:0x%04X is_notify:%u",
            param->notify.conn_id, MAC2STR(param->notify.remote_bda), param->notify.handle, param->notify.is_notify);
        ESP_LOG_BUFFER_HEX(TAG, param->notify.value, param->notify.value_len);
        if ((char_elem_tx.char_handle == param->notify.handle) && param->notify.is_notify) {
            ESP_LOGI(TAG, "recv char tx notify");
        }
        break;
    case ESP_GATTC_WRITE_CHAR_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_WRITE_CHAR_EVT, status:0x%02X conn_id:0x%04X handle:0x%04X offset:%u",
            param->write.status, param->write.conn_id, param->write.handle, param->write.offset);
        esp_ble_gattc_prepare_write(gattc_if, param->write.conn_id, char_elem_rx.char_handle,
            0, strlen(prep_write_data1), (uint8_t *)prep_write_data1, ESP_GATT_AUTH_REQ_NONE); // "hi, "
        break;
    case ESP_GATTC_WRITE_DESCR_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_WRITE_DESCR_EVT, status:0x%02X conn_id:0x%04X handle:0x%04X offset:%u",
            param->write.status, param->write.conn_id, param->write.handle, param->write.offset);
        break;
    case ESP_GATTC_PREP_WRITE_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_PREP_WRITE_EVT, status:0x%02X conn_id:0x%04X handle:0x%04X offset:%u",
            param->write.status, param->write.conn_id, param->write.handle, param->write.offset); // why status:0x04 offset:0 ?
        if (0 == prep_write_cnt) {
            esp_ble_gattc_prepare_write(gattc_if, param->write.conn_id, char_elem_rx.char_handle,
                strlen(prep_write_data1), strlen(prep_write_data2), (uint8_t *)prep_write_data2, ESP_GATT_AUTH_REQ_NONE); // "shijie "
        } else if (1 == prep_write_cnt) {
            esp_ble_gattc_prepare_write(gattc_if, param->write.conn_id, char_elem_rx.char_handle,
                strlen(prep_write_data1) + strlen(prep_write_data2), strlen(prep_write_data3), (uint8_t *)prep_write_data3, ESP_GATT_AUTH_REQ_NONE); // "nihao"
        } else if (2 == prep_write_cnt) {
            esp_ble_gattc_execute_write(gattc_if, param->write.conn_id, true);
        }
        prep_write_cnt++;
        break;
    case ESP_GATTC_EXEC_EVT:
        ESP_LOGI(TAG, "ESP_GATTC_EXEC_EVT, status:0x%02X conn_id:0x%04X", param->exec_cmpl.status, param->exec_cmpl.conn_id);
        break;
    default:
        ESP_LOGW(TAG, "unknown GATTC event:%u", event);
        break;
    }
}

void app_main(void) {
    esp_err_t err = ESP_OK;
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

    esp_bt_controller_init(&bt_cfg);
    esp_bt_controller_enable(ESP_BT_MODE_BLE);
    esp_bluedroid_init();
    esp_bluedroid_enable();
    esp_ble_gap_register_callback(gap_cb);
    esp_ble_gattc_register_callback(gattc_cb);
    esp_ble_gattc_app_register(CONFIG_GATTC_APP_ID); // trigger ESP_GATTC_REG_EVT
    esp_ble_gatt_set_local_mtu(500);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
