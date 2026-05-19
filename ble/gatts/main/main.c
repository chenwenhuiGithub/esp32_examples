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
#define CONFIG_GATTS_SVC_INSTID_CUSTOM                  0x02
#define CONFIG_GATTS_SERVER_ATT_MTU                     500

enum {
    IDX_SVC_BATTERY = 0,
    IDX_CHAR_DECL_BATTERY,
    IDX_CHAR_VAL_BATTERY,
    IDX_MAX_BATTERY,
};

enum {
    IDX_SVC_CUSTOM = 0,
    IDX_CHAR_DECL_RX,
    IDX_CHAR_VAL_RX,
    IDX_CHAR_DECL_TX,
    IDX_CHAR_VAL_TX,
    IDX_CHAR_DESC_CCC_TX,
    IDX_MAX_CUSTOM,
};

#pragma pack(1)
typedef struct {
    uint8_t prop;
    uint16_t handle;
    uint16_t uuid;
} char_decl_t;
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
static uint16_t real_mtu = 0; // exchanged ATT_MTU

static const uint16_t uuid_pri_svc               = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t uuid_char_decl             = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t uuid_char_desc_ccc         = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
static const uint16_t uuid_svc_battery           = ESP_GATT_UUID_BATTERY_SERVICE_SVC;
static const uint16_t uuid_svc_custom            = 0x18FF;
static const uint16_t uuid_obj_battery           = ESP_GATT_UUID_BATTERY_LEVEL;
static const uint16_t uuid_obj_rx                = 0x2AFE;
static const uint16_t uuid_obj_tx                = 0x2AFF;
static char_decl_t char_decl_battery             = {
    .prop = ESP_GATT_CHAR_PROP_BIT_READ,
    .handle = 0x0000,
    .uuid = uuid_obj_battery
};
static char_decl_t char_decl_rx                  = {
    .prop = ESP_GATT_CHAR_PROP_BIT_WRITE_NR | ESP_GATT_CHAR_PROP_BIT_WRITE,
    .handle = 0x0000,
    .uuid = uuid_obj_rx
};
static char_decl_t char_decl_tx                  = {
    .prop = ESP_GATT_CHAR_PROP_BIT_NOTIFY | ESP_GATT_CHAR_PROP_BIT_INDICATE,
    .handle = 0x0000,
    .uuid = uuid_obj_tx
};
static uint8_t char_val_battery                  = 25; // 25%
static uint8_t char_val_rx[1024]                 = {0};
static uint8_t char_val_tx[1024]                 = {0};
static uint16_t char_desc_ccc_tx                 = 0x0003; // bit0 - notify, bit1 - indication
static uint16_t handles_battery[IDX_MAX_BATTERY] = {0};
static uint16_t handles_custom[IDX_MAX_CUSTOM]   = {0};
static uint32_t char_val_rx_len                  = 0; // for prepare write


/*
att_handle(2B)  att_type(UUID, 2B/16B)                      att_value(0-512B)                               att_permission

// BATTERY service
0x0028          0x2800(PRIMARY_SERVICE)                     0x180F(SERVICE_BATTERY)                         PERMISSION_READ
0x0029          0x2803(CHARACTERISTIC_DECLARATION)          0x02(CHARACTERISTIC_PROPERITY_READ)             PERMISSION_READ
                                                            0x002A(handle)
                                                            0x2A19(OBJECT_BATTERY_LEVEL)
0x002A          0x2A19(OBJECT_BATTERY_LEVEL)                [1B]0x19                                        PERMISSION_READ

// CUSTOM service
0x002B          0x2800(PRIMARY_SERVICE)                     0x18FF(SERVICE_CUSTOM)                          PERMISSION_READ
0x002C          0x2803(CHARACTERISTIC_DECLARATION)          0x04(CHARACTERISTIC_PROPERITY_WRITE/WRITE_NR)   PERMISSION_READ
                                                            0x002D(handle)
                                                            0x2AFE(OBJECT_CUSTOM_RX)
0x002D          0x2AFE(OBJECT_CUSTOM_RX)                    [1024B]                                         PERMISSION_WRITE
0x002E          0x2803(CHARACTERISTIC_DECLARATION)          0x10(CHARACTERISTIC_PROPERITY_NOTIFY/INDICATE)  PERMISSION_READ
                                                            0x002F(handle)
                                                            0x2AFF(OBJECT_CUSTOM_TX)
0x002F          0x2AFF(OBJECT_CUSTOM_TX)                    [1024B]                                         PERMISSION_READ
0x0030          0x2902(CHARACTERISTIC_DESCRIPTOR_CCC)       [2B]0x0001                                      PERMISSION_WRITE
*/

static const esp_gatts_attr_db_t attr_db_battery[IDX_MAX_BATTERY] = {
    // service declaration
    [IDX_SVC_BATTERY] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP, // response attribute read/write opcode, access db or ram?
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_pri_svc,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(uuid_svc_battery),
        .att_desc.length = sizeof(uuid_svc_battery),
        .att_desc.value = (uint8_t *)&uuid_svc_battery // value memory share or copy to db?
    },

    // characteristic declaration
    [IDX_CHAR_DECL_BATTERY] = {
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

static const esp_gatts_attr_db_t attr_db_custom[IDX_MAX_CUSTOM] = {
    // service declaration
    [IDX_SVC_CUSTOM] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_pri_svc,
        .att_desc.perm = ESP_GATT_PERM_READ,
        .att_desc.max_length = sizeof(uuid_svc_custom),
        .att_desc.length = sizeof(uuid_svc_custom),
        .att_desc.value = (uint8_t *)&uuid_svc_custom
    },

    // characteristic declaration
    [IDX_CHAR_DECL_RX] = {
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
    [IDX_CHAR_DECL_TX] = {
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
    [IDX_CHAR_DESC_CCC_TX] = {
        .attr_control.auto_rsp = ESP_GATT_AUTO_RSP,
        .att_desc.uuid_length = ESP_UUID_LEN_16,
        .att_desc.uuid_p = (uint8_t *)&uuid_char_desc_ccc,
        .att_desc.perm = ESP_GATT_PERM_WRITE,
        .att_desc.max_length = sizeof(char_desc_ccc_tx),
        .att_desc.length = sizeof(char_desc_ccc_tx),
        .att_desc.value = (uint8_t *)&char_desc_ccc_tx
    }
};


static void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    switch (event) {
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT, status:0x%04x", param->adv_data_raw_cmpl.status);
        break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT, status:0x%04x", param->scan_rsp_data_raw_cmpl.status);
        break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_ADV_START_COMPLETE_EVT, status:0x%04x", param->adv_start_cmpl.status);
        break;
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT, status:0x%04x", param->adv_stop_cmpl.status);
        break;
    case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT, status:0x%04x addr:"MACSTR" min_int:%u max_int:%u conn_int:%u latency:%u, timeout:%u",
            param->update_conn_params.status, MAC2STR(param->update_conn_params.bda), param->update_conn_params.min_int, param->update_conn_params.max_int,
            param->update_conn_params.conn_int, param->update_conn_params.latency, param->update_conn_params.timeout);
        break;
    case ESP_GAP_BLE_SET_PKT_LENGTH_COMPLETE_EVT:
        ESP_LOGI(TAG, "ESP_GAP_BLE_SET_PKT_LENGTH_COMPLETE_EVT, status:0x%04x rx_len:%u tx_len:%u",
            param->pkt_data_length_cmpl.status, param->pkt_data_length_cmpl.params.rx_len, param->pkt_data_length_cmpl.params.tx_len);
        break;
    default:
        ESP_LOGW(TAG, "unknown GAP event:%u", event);
        break;
    }
}


// esp_ble_gatts_create_attr_tab(esp_gatts_attr_db_t *gatts_attr_db, esp_gatt_if_t gatts_if, uint16_t max_nb_attr, uint8_t srvc_inst_id);
    // 1. malloc service declaration att_db
    // 2. malloc characteristic declaration and value att_db
    // 3. malloc characteristic descriptor att_db
    // 4. trigger ESP_GATTS_CREAT_ATTR_TAB_EVT

// esp_ble_gatts_set_attr_value(uint16_t attr_handle, uint16_t length, const uint8_t *value);
    // 1. update characteristic value or descriptor in att_db
    // 2. trigger ESP_GATTS_SET_ATTR_VAL_EVT

// esp_ble_gatts_get_attr_value(uint16_t attr_handle, uint16_t *length, const uint8_t **value);
    // 1. read from att_db, return the point of att_db

// esp_ble_gatts_send_indicate(esp_gatt_if_t gatts_if, uint16_t conn_id, uint16_t attr_handle, uint16_t value_len, uint8_t *value, bool need_confirm);
    // 1. send ATT_HANDLE_VALUE_IND/ATT_HANDLE_VALUE_NTF
    // 2. if ATT_HANDLE_VALUE_NTF, trigger ESP_GATTS_CONF_EVT

// esp_ble_gatts_send_response(esp_gatt_if_t gatts_if, uint16_t conn_id, uint32_t trans_id, esp_gatt_status_t status, esp_gatt_rsp_t *rsp);
    // 1. response ATT_XXX_RSP
    // 2. trigger ESP_GATTS_RESPONSE_EVT

// gatt_server_handle_client_req(tGATT_TCB *p_tcb, uint8_t op_code, uint16_t len, uint8_t *p_data);
    // case GATT_REQ_MTU:
        // 1. exchange ATT_MTU
        // 2. stack response ATT_EXCHANGE_MTU_RSP
        // 3. trigger ESP_GATTS_MTU_EVT(mtu(exchanged ATT_MTU))

    // case GATT_REQ_READ:
    // case GATT_REQ_READ_BLOB:
        // 1. if read service/characteristic declaration, stack response ATT_READ_RSP/ATT_READ_BLOB_RSP, NOT trigger event
        // 2. if read characteristic value or descriptor
        //      a. if GATT_RSP_BY_STACK
        //          1). read from att_db
        //          2). trigger ESP_GATTS_READ_EVT(handle,is_long(ATT_READ_BLOB_REQ),offset,need_rsp(false))
        //          3). stack response ATT_READ_RSP/ATT_READ_BLOB_RSP
        //      b. if GATT_RSP_BY_APP
        //          1). trigger ESP_GATTS_READ_EVT(handle,is_long(ATT_READ_BLOB_REQ),offset,need_rsp(true))
        //          2). need user response ATT_READ_RSP/ATT_READ_BLOB_RSP, via call esp_ble_gatts_send_response() in ESP_GATTS_READ_EVT event

    // case GATT_REQ_WRITE:
    // case GATT_CMD_WRITE:
        // 1. if GATT_RSP_BY_STACK
        //      a. update characteristic value or descriptor in att_db
        //      b. trigger ESP_GATTS_WRITE_EVT(handle,is_prep(false),offset(0),need_rsp(false),value,len)
        //      a. if GATT_REQ_WRITE, stack response ATT_WRITE_RSP
        // 2. if GATT_RSP_BY_APP
        //      a. trigger ESP_GATTS_WRITE_EVT(handle,is_prep(false),offset(0),need_rsp(GATT_REQ_WRITE),value,len)
        //      c. if GATT_REQ_WRITE, need user response ATT_WRITE_RSP, via call esp_ble_gatts_send_response() in ESP_GATTS_WRITE_EVT event

    // case GATT_REQ_PREPARE_WRITE:
        // 1. if GATT_RSP_BY_STACK
        //      a. queue data to ram
        //      b. stack response ATT_PREPARE_WRITE_RSP
        //      c. trigger ESP_GATTS_WRITE_EVT(handle,is_prep(true),offset,need_rsp(false),value)
        // 2. if GATT_RSP_BY_APP
        //      a. trigger ESP_GATTS_WRITE_EVT(handle,is_prep(true),offset,need_rsp(true),value)
        //      b. need user response ATT_PREPARE_WRITE_RSP, via call esp_ble_gatts_send_response() in ESP_GATTS_WRITE_EVT event

    // case GATT_REQ_EXEC_WRITE:
        // 1. dequeue data from ram, update characteristic value or descriptor in att_db
        // 2. trigger ESP_GATTS_EXEC_WRITE_EVT(flag)
        // 3. need user response ATT_EXECUTE_WRITE_RSP, via call esp_ble_gatts_send_response() in ESP_GATTS_EXEC_WRITE_EVT event

static void gatts_cb(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
    switch (event) {
    case ESP_GATTS_REG_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_REG_EVT, status:0x%02x app_id:0x%04x", param->reg.status, param->reg.app_id);
        esp_ble_gap_config_adv_data_raw(adv_data, sizeof(adv_data));
        esp_ble_gap_config_scan_rsp_data_raw(scan_rsp_data, sizeof(scan_rsp_data));
        esp_ble_gatts_create_attr_tab(attr_db_battery, gatts_if, IDX_MAX_BATTERY, CONFIG_GATTS_SVC_INSTID_BATTERY); // trigger ESP_GATTS_CREAT_ATTR_TAB_EVT
        esp_ble_gatts_create_attr_tab(attr_db_custom, gatts_if, IDX_MAX_CUSTOM, CONFIG_GATTS_SVC_INSTID_CUSTOM);
        esp_ble_gap_start_advertising(&adv_params);
        break;
    case ESP_GATTS_CREAT_ATTR_TAB_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_CREAT_ATTR_TAB_EVT, status:0x%02x svc_uuid:0x%04x svc_inst_id:0x%02x num_handle:%u",
            param->add_attr_tab.status, param->add_attr_tab.svc_uuid.uuid.uuid16, param->add_attr_tab.svc_inst_id, param->add_attr_tab.num_handle);
        if (CONFIG_GATTS_SVC_INSTID_BATTERY == param->add_attr_tab.svc_inst_id) {
            ESP_LOGI(TAG, "handles:0x%04x 0x%04x 0x%04x", param->add_attr_tab.handles[0], param->add_attr_tab.handles[1], param->add_attr_tab.handles[2]);
            memcpy(handles_battery, param->add_attr_tab.handles, sizeof(uint16_t) * param->add_attr_tab.num_handle);
            esp_ble_gatts_start_service(handles_battery[IDX_SVC_BATTERY]); // trigger ESP_GATTS_START_EVT
        } else if (CONFIG_GATTS_SVC_INSTID_CUSTOM == param->add_attr_tab.svc_inst_id) {
            ESP_LOGI(TAG, "handles:0x%04x 0x%04x 0x%04x 0x%04x 0x%04x 0x%04x", param->add_attr_tab.handles[0], param->add_attr_tab.handles[1],
                param->add_attr_tab.handles[2], param->add_attr_tab.handles[3], param->add_attr_tab.handles[4], param->add_attr_tab.handles[5]);
            memcpy(handles_custom, param->add_attr_tab.handles, sizeof(uint16_t) * param->add_attr_tab.num_handle);
            esp_ble_gatts_start_service(handles_custom[IDX_SVC_CUSTOM]);
        } else {
            ESP_LOGE(TAG, "unknown svc_inst_id:0x%02x", param->add_attr_tab.svc_inst_id);
        }
        break;
    case ESP_GATTS_START_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_START_EVT, status:0x%02x svc_handle:0x%04x", param->start.status, param->start.service_handle);
        if (param->start.service_handle == handles_custom[IDX_SVC_CUSTOM]) {
            esp_ble_gatts_show_local_database();
        }
        break;
    case ESP_GATTS_CONNECT_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_CONNECT_EVT, conn_id:0x%04x role:0x%02x(0-master,1-slave) addr:"MACSTR" addr_type:0x%02x(0-public,1-random) interval:%u latency:%u timeout:%u",
            param->connect.conn_id, param->connect.link_role, MAC2STR(param->connect.remote_bda), param->connect.ble_addr_type,
            param->connect.conn_params.interval, param->connect.conn_params.latency, param->connect.conn_params.timeout);
        
        esp_ble_conn_update_params_t conn_update_params = {0};
        conn_update_params.latency = 0;
        conn_update_params.min_int = 0x10; // 0x10 * 1.25ms = 20ms
        conn_update_params.max_int = 0x20; // 0x20 * 1.25ms = 40ms
        conn_update_params.timeout = 400;  // 400 * 10ms = 4000ms
        memcpy(conn_update_params.bda, param->connect.remote_bda, sizeof(esp_bd_addr_t));
        esp_ble_gap_update_conn_params(&conn_update_params);
        break;
    case ESP_GATTS_DISCONNECT_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_DISCONNECT_EVT, conn_id:0x%04x addr:"MACSTR" reason:0x%04x",
            param->disconnect.conn_id, MAC2STR(param->disconnect.remote_bda), param->disconnect.reason);
        esp_ble_gap_start_advertising(&adv_params);
        break;
    case ESP_GATTS_MTU_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_MTU_EVT, conn_id:0x%04x mtu:%u", param->mtu.conn_id, param->mtu.mtu);
        real_mtu = param->mtu.mtu;
        break;
    case ESP_GATTS_READ_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_READ_EVT, conn_id:0x%04x trans_id:0x%08x addr:"MACSTR" handle:0x%04x offset:%u is_long:%u need_rsp:%u",
            param->read.conn_id, param->read.trans_id, MAC2STR(param->read.bda), param->read.handle, param->read.offset, param->read.is_long, param->read.need_rsp);
        if (param->read.need_rsp) {
            uint16_t att_len = 0;
            const uint8_t *att_val = NULL;
            esp_gatt_rsp_t gatt_rsp = {0};

            esp_ble_gatts_get_attr_value(param->read.handle, &att_len, &att_val);

            gatt_rsp.handle = param->read.handle;
            gatt_rsp.attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
            gatt_rsp.attr_value.handle = param->read.handle;
            if (param->read.is_long) {
                gatt_rsp.attr_value.offset = param->read.offset;
                gatt_rsp.attr_value.len = (att_len - param->read.offset >= (real_mtu - 1)) ? real_mtu - 1 : att_len - param->read.offset;
                memcpy(gatt_rsp.attr_value.value, att_val + param->read.offset, gatt_rsp.attr_value.len);
            } else {
                gatt_rsp.attr_value.offset = 0;
                gatt_rsp.attr_value.len = (att_len >= (real_mtu - 1)) ? real_mtu - 1 : att_len;
                memcpy(gatt_rsp.attr_value.value, att_val, gatt_rsp.attr_value.len);
            }
            esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id, ESP_GATT_OK, &gatt_rsp); // trigger ESP_GATTS_RESPONSE_EVT
        }

        if (handles_battery[IDX_CHAR_VAL_BATTERY] == param->read.handle) {
            char_val_battery++;
            esp_ble_gatts_set_attr_value(handles_battery[IDX_CHAR_VAL_BATTERY], 1, &char_val_battery); // trigger ESP_GATTS_SET_ATTR_VAL_EVT
        }
        break;
    case ESP_GATTS_WRITE_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_WRITE_EVT, conn_id:0x%04x trans_id:0x%08x addr:"MACSTR" handle:0x%04x offset:%u need_rsp:%u is_prep:%u len:%u",
            param->write.conn_id, param->write.trans_id, MAC2STR(param->write.bda), param->write.handle, param->write.offset, param->write.need_rsp, param->write.is_prep, param->write.len);
        ESP_LOG_BUFFER_HEX(TAG, param->write.value, param->write.len);
        if (param->write.need_rsp) {
            esp_gatt_rsp_t gatt_rsp = {0};

            if (param->write.is_prep) {    
                gatt_rsp.handle = param->write.handle;
                gatt_rsp.attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
                gatt_rsp.attr_value.handle = param->write.handle;
                gatt_rsp.attr_value.offset = param->write.offset;
                gatt_rsp.attr_value.len = param->write.len;
                memcpy(gatt_rsp.attr_value.value, param->write.value, param->write.len);
                esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, &gatt_rsp);
            } else {
                esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
            }
        }
        
        if (handles_custom[IDX_CHAR_DESC_CCC_TX] == param->write.handle) {
            char_desc_ccc_tx = (param->write.value[1] << 8) + param->write.value[0];
            if (0x0000 == char_desc_ccc_tx) {
                ESP_LOGI(TAG, "custom_tx notify/indicate disable");
            } else if (0x0001 == char_desc_ccc_tx) {
                ESP_LOGI(TAG, "custom_tx notify enable");
                esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, handles_custom[IDX_CHAR_VAL_TX], strlen("notify enable"), (uint8_t *)"notify enable", false); // trigger ESP_GATTS_CONF_EVT
            } else if (0x0002 == char_desc_ccc_tx) {
                ESP_LOGI(TAG, "custom_tx indicate enable");
                esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, handles_custom[IDX_CHAR_VAL_TX], strlen("indicate enable"), (uint8_t *)"indicate enable", true);
            } else {
                ESP_LOGE(TAG, "unknown ccc:0x%04x", char_desc_ccc_tx);
            }
        }
        
        if (handles_custom[IDX_CHAR_VAL_RX] == param->write.handle) {
            if (param->write.is_prep) {
                memcpy(char_val_rx + param->write.offset, param->write.value, param->write.len);
                char_val_rx_len = param->write.offset + param->write.len;
            } else {
                ESP_LOG_BUFFER_HEX(TAG, param->write.value, param->write.len);
            }
        }
        break;
    case ESP_GATTS_EXEC_WRITE_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_EXEC_WRITE_EVT, conn_id:0x%04x trans_id:0x%08x addr:"MACSTR" write_flag:0x%02x(0-cancel,1-exec)",
            param->exec_write.conn_id, param->exec_write.trans_id, MAC2STR(param->exec_write.bda), param->exec_write.exec_write_flag);
        esp_ble_gatts_send_response(gatts_if, param->exec_write.conn_id, param->exec_write.trans_id, ESP_GATT_OK, NULL);

        if (ESP_GATT_PREP_WRITE_EXEC == param->exec_write.exec_write_flag) {
            ESP_LOG_BUFFER_HEX(TAG, char_val_rx, char_val_rx_len);
        }
        break;
    case ESP_GATTS_SET_ATTR_VAL_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_SET_ATTR_VAL_EVT, status:0x%02x svc_handle:0x%04x attr_handle:0x%04x",
            param->set_attr_val.status, param->set_attr_val.srvc_handle, param->set_attr_val.attr_handle);
        break;
    case ESP_GATTS_RESPONSE_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_RESPONSE_EVT, status:0x%02x conn_id:0x%04x handle:0x%04x",
            param->rsp.status, param->rsp.conn_id, param->rsp.handle);
        break;
    case ESP_GATTS_CONF_EVT:
        ESP_LOGI(TAG, "ESP_GATTS_CONF_EVT, status:0x%02x conn_id:0x%04x handle:0x%04x len:%u",
            param->conf.status, param->conf.conn_id, param->conf.handle, param->conf.len);
        ESP_LOG_BUFFER_HEX(TAG, param->conf.value, param->conf.len);
        break;
    default:
        ESP_LOGW(TAG, "unknown GATTS event:%u", event);
        break;
    }
}

void app_main(void) {
    esp_err_t err = ESP_OK;

    err = nvs_flash_init();
    if (ESP_ERR_NVS_NO_FREE_PAGES == err || ESP_ERR_NVS_NEW_VERSION_FOUND == err) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "nvs_flash_init error:%d", err);
        return;
    }

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    esp_bt_controller_init(&bt_cfg);
    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    esp_bt_controller_enable(ESP_BT_MODE_BLE);
    esp_bluedroid_init();
    esp_bluedroid_enable();
    esp_ble_gap_register_callback(gap_cb);
    esp_ble_gatts_register_callback(gatts_cb);
    esp_ble_gatts_app_register(CONFIG_GATTS_APP_ID); // trigger ESP_GATTS_REG_EVT
    esp_ble_gatt_set_local_mtu(CONFIG_GATTS_SERVER_ATT_MTU);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
