#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_mac.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"


#define CONFIG_GATTS_APP_ID                             0x5AA5
#define CONFIG_GATTS_SVC_INSTID_BATTERY                 0x01
#define CONFIG_GATTS_SVC_INSTID_TEST                    0x02

enum {
    IDX_SVC_BATTERY = 0,
    IDX_CHAR_DEC_BATTERY,
    IDX_CHAR_VAL_BATTERY,
    IDX_MAX_BATTERY,
};

enum {
    IDX_SVC_TEST = 0,
    IDX_CHAR_DEC_RX,
    IDX_CHAR_VAL_RX,
    IDX_CHAR_DEC_TX,
    IDX_CHAR_VAL_TX,
    IDX_CHAR_CCC_TX,
    IDX_MAX_TEST,
};

#pragma pack(1)
typedef struct {
    uint8_t char_prop;
    uint16_t char_handle;
    uint16_t char_obj_type;
} char_dec_value_t;
#pragma pack()


static const char *TAG = "ble_gatts";
static uint8_t adv_data[] = {
    0x02, ESP_BLE_AD_TYPE_FLAG, 0x06,
    0x03, ESP_BLE_AD_TYPE_16SRV_CMPL, 0xFF, 0x00
};
static uint8_t scan_rsp_data[] = {
    0x11, ESP_BLE_AD_TYPE_NAME_CMPL, 'e', 's', 'p', '3', '2', '_', 'g', 'a', 't', 't', 's', '_', 'd','e', 'm', 'o'
};
static esp_ble_adv_params_t adv_params = {
    .adv_int_min         = 0x20,
    .adv_int_max         = 0x40,
    .adv_type            = ADV_TYPE_IND,
    .own_addr_type       = BLE_ADDR_TYPE_PUBLIC,
    .channel_map         = ADV_CHNL_ALL,
    .adv_filter_policy   = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY
};
static esp_ble_conn_update_params_t conn_update_params = {0};
static esp_gatt_rsp_t gatt_rsp = {0};

/*
att_handle(2B)  att_type(UUID, 2B/16B)                      att_value(0-512B)                           att_permission
// BATTERY service
0x0028          0x2800(PRIMARY_SERVICE)                     0x180F(SERVICE_BATTERY)                     PERMISSION_READ
0x0029          0x2803(CHARACTERISTIC_DECLARATION)          0x02(CHARACTERISTIC_PROPERITY_READ)         PERMISSION_READ
                                                            0x002A(handle)
                                                            0x2A19(OBJECT_BATTERY_LEVEL)
0x002A          0x2A19(OBJECT_BATTERY_LEVEL)                [1B]0x19                                    PERMISSION_READ

// TEST service
0x002B          0x2800(PRIMARY_SERVICE)                     0x18FF(SERVICE_TEST)                        PERMISSION_READ
0x002C          0x2803(CHARACTERISTIC_DECLARATION)          0x04(CHARACTERISTIC_PROPERITY_WRITE_NR)     PERMISSION_READ
                                                            0x002D(handle)
                                                            0x2AFE(OBJECT_TEST_RX)
0x002D          0x2AFE(OBJECT_TEST_RX)                      [1024B]                                     PERMISSION_WRITE
0x002E          0x2803(CHARACTERISTIC_DECLARATION)          0x10(CHARACTERISTIC_PROPERITY_NOTIFY)       PERMISSION_READ
                                                            0x002F(handle)
                                                            0x2AFF(OBJECT_TEST_TX)
0x002F          0x2AFF(OBJECT_TEST_TX)                      [1024B]                                     PERMISSION_READ
0x0030          0x2902(CHARACTERISTIC_DESCRIPTOR_CCC)       [2B]0x0001                                  PERMISSION_READ|WRITE
*/

static const uint16_t uuid_pri_svc               = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t uuid_char_decl             = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t uuid_char_desc_ccc         = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
static const uint16_t uuid_svc_battery           = ESP_GATT_UUID_BATTERY_SERVICE_SVC;
static const uint16_t uuid_svc_test              = 0x18FF;
static const uint16_t uuid_obj_battery           = ESP_GATT_UUID_BATTERY_LEVEL;
static const uint16_t uuid_obj_rx                = 0x2AFE;
static const uint16_t uuid_obj_tx                = 0x2AFF;
static char_dec_value_t char_decl_battery        = {.char_prop = ESP_GATT_CHAR_PROP_BIT_READ,     .char_handle = 0x0000, .char_obj_type = uuid_obj_battery};
static char_dec_value_t char_decl_rx             = {.char_prop = ESP_GATT_CHAR_PROP_BIT_WRITE_NR, .char_handle = 0x0000, .char_obj_type = uuid_obj_rx};
static char_dec_value_t char_decl_tx             = {.char_prop = ESP_GATT_CHAR_PROP_BIT_NOTIFY,   .char_handle = 0x0000, .char_obj_type = uuid_obj_tx};
static uint8_t char_val_battery                  = 0x19; // 25%
static uint8_t char_val_rx[1024]                 = {0};
static uint8_t char_val_tx[1024]                 = {0};
static uint8_t char_desc_tx_ccc[2]               = {0x01, 0x00}; // bit0 - notify, bit1 - indication
static uint16_t handles_battery[IDX_MAX_BATTERY] = {0};
static uint16_t handles_test[IDX_MAX_TEST]       = {0};
static uint32_t char_val_rx_len                  = 0; // for prepare write

static const esp_gatts_attr_db_t gatts_db_battery[IDX_MAX_BATTERY] = {
    // service declaration
    [IDX_SVC_BATTERY] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_pri_svc,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(uuid_svc_battery),
        .att_desc.length = sizeof(uuid_svc_battery),
        .att_desc.value = (uint8_t *)&uuid_svc_battery
    },

    // characteristic declaration
    [IDX_CHAR_DEC_BATTERY] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_char_decl,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(char_decl_battery),
        .att_desc.length = sizeof(char_decl_battery),
        .att_desc.value = (uint8_t *)&char_decl_battery
    },

    // characteristic value
    [IDX_CHAR_VAL_BATTERY] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_obj_battery,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(char_val_battery),
        .att_desc.length = sizeof(char_val_battery),
        .att_desc.value = &char_val_battery
    }
};

static const esp_gatts_attr_db_t gatts_db_test[IDX_MAX_TEST] = {
    // service declaration
    [IDX_SVC_TEST] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_pri_svc,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(uuid_svc_test),
        .att_desc.length = sizeof(uuid_svc_test),
        .att_desc.value = (uint8_t *)&uuid_svc_test
    },

    // characteristic declaration
    [IDX_CHAR_DEC_RX] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_char_decl,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(char_decl_rx),
        .att_desc.length = sizeof(char_decl_rx),
        .att_desc.value = (uint8_t *)&char_decl_rx
    },

    // characteristic value
    [IDX_CHAR_VAL_RX] = {
        .attr_control.auto_rsp = ESP_GATT_RSP_BY_APP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_obj_rx,
        .att_desc.perm = ESP_GATT_PERM_WRITE,
        .att_desc.max_length = sizeof(char_val_rx),
        .att_desc.length = sizeof(char_val_rx),
        .att_desc.value = char_val_rx
    },

    // characteristic declaration
    [IDX_CHAR_DEC_TX] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_char_decl,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(char_decl_tx),
        .att_desc.length = sizeof(char_decl_tx),
        .att_desc.value = (uint8_t *)&char_decl_tx
    },

    // characteristic value
    [IDX_CHAR_VAL_TX] = {
        .attr_control.auto_rsp = ESP_GATT_RSP_BY_APP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_obj_tx,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(char_val_tx),
        .att_desc.length = sizeof(char_val_tx),
        .att_desc.value = char_val_tx
    },

    // client characteristic configuration descriptor
    [IDX_CHAR_CCC_TX] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_char_desc_ccc,
        .att_desc.perm = ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
        .att_desc.max_length = sizeof(char_desc_tx_ccc),
        .att_desc.length = sizeof(char_desc_tx_ccc),
        .att_desc.value = char_desc_tx_ccc
    }
};

static void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    switch (event) {
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT, status:0x%04X", param->adv_data_raw_cmpl.status);
        break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT, status:0x%04X", param->scan_rsp_data_raw_cmpl.status);
        break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_ADV_START_COMPLETE_EVT, status:0x%04X", param->adv_start_cmpl.status);
        break;
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT, status:0x%04X", param->adv_stop_cmpl.status);
        break;
    case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT, status:0x%04X addr:"MACSTR" min_int:%u max_int:%u conn_int:%u latency:%u, timeout:%u",
            param->update_conn_params.status, MAC2STR(param->update_conn_params.bda), param->update_conn_params.min_int, param->update_conn_params.max_int,
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

static void gatts_cb(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
    switch (event) {
    case ESP_GATTS_REG_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_REG_EVT, status:0x%02X app_id:0x%04X", param->reg.status, param->reg.app_id);
        esp_ble_gap_config_adv_data_raw(adv_data, sizeof(adv_data));
        esp_ble_gap_config_scan_rsp_data_raw(scan_rsp_data, sizeof(scan_rsp_data));
        esp_ble_gap_start_advertising(&adv_params);
        esp_ble_gatts_create_attr_tab(gatts_db_battery, gatts_if, IDX_MAX_BATTERY, CONFIG_GATTS_SVC_INSTID_BATTERY); // trigger ESP_GATTS_CREAT_ATTR_TAB_EVT
        esp_ble_gatts_create_attr_tab(gatts_db_test, gatts_if, IDX_MAX_TEST, CONFIG_GATTS_SVC_INSTID_TEST);
        break;
    case ESP_GATTS_CREAT_ATTR_TAB_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_CREAT_ATTR_TAB_EVT, status:0x%02X svc_uuid:0x%04X svc_inst_id:0x%02X num_handle:%u",
            param->add_attr_tab.status, param->add_attr_tab.svc_uuid.uuid.uuid16, param->add_attr_tab.svc_inst_id, param->add_attr_tab.num_handle);
        if (CONFIG_GATTS_SVC_INSTID_BATTERY == param->add_attr_tab.svc_inst_id) {
            ESP_LOGI(TAG, "handles:0x%04X 0x%04X 0x%04X", param->add_attr_tab.handles[0], param->add_attr_tab.handles[1], param->add_attr_tab.handles[2]);
            memcpy(handles_battery, param->add_attr_tab.handles, sizeof(uint16_t) * param->add_attr_tab.num_handle);
            esp_ble_gatts_start_service(handles_battery[IDX_SVC_BATTERY]); // trigger ESP_GATTS_START_EVT
        } else if (CONFIG_GATTS_SVC_INSTID_TEST == param->add_attr_tab.svc_inst_id) {
            ESP_LOGI(TAG, "handles:0x%04X 0x%04X 0x%04X 0x%04X 0x%04X 0x%04X", param->add_attr_tab.handles[0], param->add_attr_tab.handles[1],
                param->add_attr_tab.handles[2], param->add_attr_tab.handles[3], param->add_attr_tab.handles[4], param->add_attr_tab.handles[5]);
            memcpy(handles_test, param->add_attr_tab.handles, sizeof(uint16_t) * param->add_attr_tab.num_handle);
            esp_ble_gatts_start_service(handles_test[IDX_SVC_TEST]);                  
        } else {
            ESP_LOGE(TAG, "unknown svc_inst_id:0x%02X", param->add_attr_tab.svc_inst_id);
        }
        break;
    case ESP_GATTS_START_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_START_EVT, status:0x%02X svc_handle:0x%04X", param->start.status, param->start.service_handle);
        break;
    case ESP_GATTS_CONNECT_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_CONNECT_EVT, conn_id:0x%04X link_role(0-master,1-slave):0x%02X addr:"MACSTR" addr_type(0-public,1-random):0x%02X interval:%u latency:%u timeout:%u",
            param->connect.conn_id, param->connect.link_role, MAC2STR(param->connect.remote_bda), param->connect.ble_addr_type,
            param->connect.conn_params.interval, param->connect.conn_params.latency, param->connect.conn_params.timeout);
        conn_update_params.latency = 0;
        conn_update_params.min_int = 0x10; // min_int = 0x10*1.25ms = 20ms
        conn_update_params.max_int = 0x20; // max_int = 0x20*1.25ms = 40ms
        conn_update_params.timeout = 400;  // timeout = 400*10ms = 4000ms
        memcpy(conn_update_params.bda, param->connect.remote_bda, sizeof(esp_bd_addr_t));
        esp_ble_gap_update_conn_params(&conn_update_params);
        break;
    case ESP_GATTS_DISCONNECT_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_DISCONNECT_EVT, conn_id:0x%04X addr:"MACSTR" reason:0x%04X",
            param->disconnect.conn_id, MAC2STR(param->disconnect.remote_bda), param->disconnect.reason);
        esp_ble_gap_start_advertising(&adv_params);
        break;
    case ESP_GATTS_MTU_EVT: // received ATT_EXCHANGE_MTU_REQ, ble stack update ATT_MTU and send ATT_EXCHANGE_MTU_RSP auto, then trigger ESP_GATTS_MTU_EVT
        ESP_LOGI(TAG, "ESP_GATTS_MTU_EVT, conn_id:0x%04X mtu:%u", param->mtu.conn_id, param->mtu.mtu);
        break;
    case ESP_GATTS_READ_EVT: // received ATT_READ_REQ, ble stack read char value from db and send ATT_READ_RSP auto, then trigger ESP_GATTS_READ_EVT
        ESP_LOGI(TAG, "ESP_GATTS_READ_EVT, conn_id:0x%04X addr:"MACSTR" handle:0x%04X offset:%u is_long:%u need_rsp:%u",
            param->read.conn_id, MAC2STR(param->read.bda), param->read.handle, param->read.offset, param->read.is_long, param->read.need_rsp);
        if (handles_battery[IDX_CHAR_VAL_BATTERY] == param->read.handle) {
            char_val_battery++; // write char value in RAM
            esp_ble_gatts_set_attr_value(handles_battery[IDX_CHAR_VAL_BATTERY], 1, &char_val_battery); // write char value in db, then trigger ESP_GATTS_SET_ATTR_VAL_EVT
        }
        break;
    case ESP_GATTS_WRITE_EVT: // received ATT_WRITE_CMD/ATT_WRITE_REQ/ATT_PREPARE_WRITE_REQ, ble stack write char value to db and send ATT_WRITE_RSP/ATT_PREPARE_WRITE_RSP auto, then trigger ESP_GATTS_WRITE_EVT
        ESP_LOGI(TAG, "ESP_GATTS_WRITE_EVT, conn_id:0x%04X addr:"MACSTR" handle:0x%04X offset:%u need_rsp:%u is_prep:%u len:%u",
            param->write.conn_id, MAC2STR(param->write.bda), param->write.handle, param->write.offset, param->write.need_rsp, param->write.is_prep, param->write.len);
        if (handles_test[IDX_CHAR_CCC_TX] == param->write.handle && param->write.len == sizeof(char_desc_tx_ccc)) {
            if (param->write.need_rsp) { // ATT_WRITE_REQ
                esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
            }

            char_desc_tx_ccc[0] = param->write.value[0]; // db and RAM are different memory
            char_desc_tx_ccc[1] = param->write.value[1];
            if (0x00 == char_desc_tx_ccc[0]) {
                ESP_LOGI(TAG, "test_tx notify/indicate disable");
            } else if (0x01 == char_desc_tx_ccc[0]) {
                ESP_LOGI(TAG, "test_tx notify enable");
                esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, handles_test[IDX_CHAR_VAL_TX], strlen("notify enable"), (uint8_t *)"notify enable", false);
            } else if (0x02 == char_desc_tx_ccc[0]) {
                ESP_LOGI(TAG, "test_tx indicate enable");
                esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, handles_test[IDX_CHAR_VAL_TX], strlen("indicate enable"), (uint8_t *)"indicate enable", true);
            } else {
                ESP_LOGE(TAG, "unknown ccc:0x%02X%02X", char_desc_tx_ccc[1], char_desc_tx_ccc[0]);
            }
        } else if (handles_test[IDX_CHAR_VAL_RX] == param->write.handle) {
            if (param->write.is_prep) { // ATT_PREPARE_WRITE_REQ
                if (param->write.need_rsp) {
                    memcpy(gatt_rsp.attr_value.value, param->write.value, param->write.len);
                    gatt_rsp.attr_value.len = param->write.len;
                    gatt_rsp.attr_value.handle = param->write.handle;
                    gatt_rsp.attr_value.offset = param->write.offset;
                    gatt_rsp.attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
                    esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, &gatt_rsp);
                }
                memcpy(char_val_rx + char_val_rx_len, param->write.value, param->write.len);
                char_val_rx_len += param->write.len;
            } else {
                if (param->write.need_rsp) { // ATT_WRITE_REQ
                    esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
                }
                ESP_LOG_BUFFER_HEX(TAG, param->write.value, param->write.len);
            }
        } else {

        }
        break;
    case ESP_GATTS_EXEC_WRITE_EVT: // received ATT_EXECUTE_WRITE_REQ, ble stack write char value to db and send ATT_EXECUTE_WRITE_RSP auto, then trigger ESP_GATTS_EXEC_WRITE_EVT
        ESP_LOGI(TAG, "ESP_GATTS_EXEC_WRITE_EVT, conn_id:0x%04X addr:"MACSTR" write_flag(0-cancel,1-exec):0x%02X",
            param->exec_write.conn_id, MAC2STR(param->exec_write.bda), param->exec_write.exec_write_flag);
        esp_ble_gatts_send_response(gatts_if, param->exec_write.conn_id, param->exec_write.trans_id, ESP_GATT_OK, NULL);
        if (ESP_GATT_PREP_WRITE_CANCEL == param->exec_write.exec_write_flag) {
            char_val_rx_len = 0;
        } else if (ESP_GATT_PREP_WRITE_EXEC == param->exec_write.exec_write_flag) {
            ESP_LOG_BUFFER_HEX(TAG, char_val_rx, char_val_rx_len);
        } else {
            ESP_LOGE(TAG, "unknown write_flag:0x%02X", param->exec_write.exec_write_flag);
        }
        break;
    case ESP_GATTS_SET_ATTR_VAL_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_SET_ATTR_VAL_EVT, status:0x%02X svc_handle:0x%04X attr_handle:0x%04X",
            param->set_attr_val.status, param->set_attr_val.srvc_handle, param->set_attr_val.attr_handle);
        break;
    default:
        ESP_LOGW(TAG, "unknown GATTS event:%u", event);
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
    esp_ble_gatts_register_callback(gatts_cb);
    esp_ble_gatts_app_register(CONFIG_GATTS_APP_ID); // trigger ESP_GATTS_REG_EVT
    esp_ble_gatt_set_local_mtu(500);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
