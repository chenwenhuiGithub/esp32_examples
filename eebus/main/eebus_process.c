#include "esp_log.h"
#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "src/common/eebus_malloc.h"
#include "src/ship/tls_certificate/tls_certificate.h"
#include "src/service/api/eebus_service_config.h"
#include "src/service/api/service_reader_interface.h"
#include "src/spine/model/electrical_connection_types.h"
#include "src/service/service/eebus_service.h"
#include "src/use_case/actor/cs/lpc/cs_lpc.h"
#include "src/use_case/actor/cs/lpp/cs_lpp.h"
#include "src/use_case/api/mu_mpc_listener_interface.h"
#include "src/use_case/actor/mu/mpc/mu_mpc_measurement.h"
#include "src/use_case/actor/mu/mpc/mu_mpc_monitor.h"
#include "src/use_case/actor/mu/mpc/mu_mpc.h"
#include "eebus_process.h"
#include "cs_lpc_cbs.h"
#include "cs_lpp_cbs.h"
#include "mu_mpc_cbs.h"


static void DestructSerReader(ServiceReaderObject *self);
static void OnRemoteSkiConnected(ServiceReaderObject *self, EebusServiceObject *service, const char *ski);
static void OnRemoteSkiDisconnected(ServiceReaderObject *self, EebusServiceObject *service, const char *ski);
static void OnRemoteServicesUpdate(ServiceReaderObject *self, EebusServiceObject *service, const Vector *entries);
static void OnShipIdUpdate(ServiceReaderObject *self, const char *ski, const char *shipd_id);
static void OnShipStateUpdate(ServiceReaderObject *self, const char *ski, SmeState state);
static bool IsWaitingForTrustAllowed(const ServiceReaderObject *self, const char *ski);
static int gen_self_sign_crt(eebus_key_t *eebus_key);
static int start_inv_service(void);


static const char *TAG = "eebus_process";

static ServiceReaderObject serviceReaderObj = {0};
static TlsCertificateObject *tlsCrtObj = NULL;
static EebusServiceConfig *serviceCfg = NULL;
static EebusServiceObject *serviceObj = NULL;
static DeviceLocalObject *devLocalObj = NULL;
static EntityLocalObject *entityInvObj = NULL;
static EntityLocalObject *entitySEAObj = NULL;
static CsLpListenerObject *csLpcListenerObj = NULL;
static CsLpListenerObject *csLppListenerObj = NULL;
static MuMpcListenerObject *muMpcListenerObj = NULL;
static CsLpUseCaseObject *csLpcUCObj = NULL;
static CsLpUseCaseObject *csLppUCObj = NULL;
static MuMpcUseCaseObject *muMpcUCObj = NULL;
static const uint32_t kHeartbeatTimeoutSeconds = 60;
static const ElectricalConnectionIdType kElectricalConnectionIdType = 0;
static const int8_t kScaleDefault = -2;
static SmeState cur_sem_state = kCmiStateInitStart;

static const ServiceReaderInterface serviceReaderIf = {
    .destruct                           = DestructSerReader,
    .on_remote_ski_connected            = OnRemoteSkiConnected,
    .on_remote_ski_disconnected         = OnRemoteSkiDisconnected,
    .on_remote_services_update          = OnRemoteServicesUpdate,
    .on_ship_id_update                  = OnShipIdUpdate,
    .on_ship_state_update               = OnShipStateUpdate,
    .is_waiting_for_trust_allowed       = IsWaitingForTrustAllowed,
};

static const CsLpListenerInterface csLpcListenerIf = {
    .destruct                           = DestructCsLpc,
    .on_remote_eg_added                 = OnCsLpcRemoteEgAdded,
    .on_remote_eg_removed               = OnCsLpcRemoteEgRemoved,
    .on_power_limit_receive             = OnCsLpcPowerLimitReceive,
    .on_failsafe_power_limit_receive    = OnCsLpcFailsafePowerLimitReceive,
    .on_failsafe_duration_receive       = OnCsLpcFailsafeDurationReceive,
    .on_heartbeat_receive               = OnCsLpcHeartbeatReceive,
};

static const CsLpListenerInterface csLppListenerIf = {
    .destruct                           = DestructCsLpp,
    .on_remote_eg_added                 = OnCsLppRemoteEgAdded,
    .on_remote_eg_removed               = OnCsLppRemoteEgRemoved,
    .on_power_limit_receive             = OnCsLppPowerLimitReceive,
    .on_failsafe_power_limit_receive    = OnCsLppFailsafePowerLimitReceive,
    .on_failsafe_duration_receive       = OnCsLppFailsafeDurationReceive,
    .on_heartbeat_receive               = OnCsLppHeartbeatReceive,
};

static const MuMpcListenerInterface muMpcListenerIf = {
    .destruct                           = DestructMuMpc,
    .on_remote_ma_added                 = OnMuMpcRemoteMaAdded,
    .on_remote_ma_removed               = OnMuMpcRemoteMaRemoved,
};

eebus_key_t g_eebus_key = {0};
eebus_mpc_measurement_data_t g_ms_data = { // 10^(-2)
    .power_total        = 1000000,
    .power_phase_a      = 100000,
    .power_phase_b      = 200000,
    .power_phase_c      = 300000,

    .energy_consumed    = 400000,
    .energy_produced    = 500000,

    .current_phase_a    = 10000,
    .current_phase_b    = 20000,
    .current_phase_c    = 30000,

    .voltage_phase_a    = 40000,
    .voltage_phase_b    = 50000,
    .voltage_phase_c    = 60000,
    .voltage_phase_ab   = 70000,
    .voltage_phase_bc   = 80000,
    .voltage_phase_ac   = 90000,

    .frequency          = 456700,
};


static void DestructSerReader(ServiceReaderObject* self) {
    if (serviceObj) {
        EEBUS_SERVICE_STOP(serviceObj);
        EebusServiceDelete(serviceObj);
        serviceObj = NULL;
    }

    if (serviceCfg) {
        EebusServiceConfigDelete(serviceCfg);
        serviceCfg = NULL;
    }

    if (csLpcUCObj) {
        UseCaseDelete(USE_CASE_OBJECT(csLpcUCObj));
        csLpcUCObj = NULL;   
        CS_LP_LISTENER_DESTRUCT(csLpcListenerObj);
        EEBUS_FREE(csLpcListenerObj);     
    }

    if (csLppUCObj) {
        UseCaseDelete(USE_CASE_OBJECT(csLppUCObj));
        csLppUCObj = NULL;   
        CS_LP_LISTENER_DESTRUCT(csLppListenerObj);
        EEBUS_FREE(csLppListenerObj);       
    }

    if (muMpcUCObj) {
        UseCaseDelete(USE_CASE_OBJECT(muMpcUCObj));
        muMpcUCObj = NULL;
        MU_MPC_LISTENER_DESTRUCT(muMpcListenerObj);
        EEBUS_FREE(muMpcListenerObj);        
    }

    ESP_LOGI(TAG, "DestructSerReader");
}

static void OnRemoteSkiConnected(ServiceReaderObject* self, EebusServiceObject* service, const char* ski) {

    ESP_LOGI(TAG, "OnRemoteSkiConnected: %s", ski);
}

static void OnRemoteSkiDisconnected(ServiceReaderObject* self, EebusServiceObject* service, const char* ski) {

    ESP_LOGI(TAG, "OnRemoteSkiDisconnected: %s", ski);
}

static void OnRemoteServicesUpdate(ServiceReaderObject* self, EebusServiceObject* service, const Vector* entries) {

    ESP_LOGI(TAG, "OnRemoteServicesUpdate");
}

static void OnShipIdUpdate(ServiceReaderObject* self, const char* ski, const char* shipd_id) {

    ESP_LOGI(TAG, "OnShipIdUpdate, ski:%s, shipd_id:%s", ski, shipd_id);
}

static void OnShipStateUpdate(ServiceReaderObject* self, const char* ski, SmeState state) {
    cur_sem_state = state;
    ESP_LOGI(TAG, "OnShipStateUpdate, ski:%s, state:%d", ski, state);
}

static bool IsWaitingForTrustAllowed(const ServiceReaderObject* self, const char* ski) {

    ESP_LOGI(TAG, "IsWaitingForTrustAllowed, ski:%s", ski); // deadcode, 当前不判断第二层允许接入开关
    return true;
}


static int gen_self_sign_crt(eebus_key_t *eebus_key) {
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    mbedtls_pk_context pk_ctx;
    mbedtls_x509write_cert x509w_crt;
    uint8_t sn[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN] = {0};

    psa_generate_random(sn, MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN);

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, 256);
    psa_generate_key(&key_attr, &key_id);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_copy_from_psa(key_id, &pk_ctx);
    mbedtls_pk_write_pubkey_pem(&pk_ctx, (unsigned char *)eebus_key->pubkey, sizeof(eebus_key->pubkey));
    mbedtls_pk_write_key_pem(&pk_ctx, (unsigned char *)eebus_key->privkey, sizeof(eebus_key->privkey));

    mbedtls_x509write_crt_init(&x509w_crt);
    mbedtls_x509write_crt_set_version(&x509w_crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&x509w_crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&x509w_crt, &pk_ctx);
    mbedtls_x509write_crt_set_ns_cert_type(&x509w_crt,
        MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER | MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING);
    mbedtls_x509write_crt_set_key_usage(&x509w_crt,
        MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
    mbedtls_x509write_crt_set_subject_name(&x509w_crt, "C=CN,ST=ZJ,L=HZ,O=SolaxPower,CN=eebus-xdongle");
    mbedtls_x509write_crt_set_issuer_name(&x509w_crt, "C=CN,ST=ZJ,L=HZ,O=SolaxPower,CN=eebus-xdongle");  
    mbedtls_x509write_crt_set_issuer_key(&x509w_crt, &pk_ctx);
    mbedtls_x509write_crt_set_serial_raw(&x509w_crt, sn, sizeof(sn));
    mbedtls_x509write_crt_set_validity(&x509w_crt, "20250101000000", "20350101000000");
    mbedtls_x509write_crt_set_basic_constraints(&x509w_crt, 1, -1);
    mbedtls_x509write_crt_set_subject_key_identifier(&x509w_crt);
    mbedtls_x509write_crt_set_authority_key_identifier(&x509w_crt);
    mbedtls_x509write_crt_pem(&x509w_crt, (unsigned char *)eebus_key->crt, sizeof(eebus_key->crt));

    mbedtls_x509write_crt_free(&x509w_crt);
    mbedtls_pk_free(&pk_ctx);
    psa_destroy_key(key_id);

    return 0;
}

static int start_inv_service(void) {
    static const MuMpcMeasurementConfig muMpcMeasurementCfg = {
        .value_source = kMeasurementValueSourceTypeMeasuredValue,
    };
    static const MuMpcMonitorEnergyConfig muMpcMonitorEnergyCfg = {
        .energy_production_cfg  = &muMpcMeasurementCfg,
        .energy_consumption_cfg = &muMpcMeasurementCfg,
    };
    static const MuMpcMonitorCurrentConfig muMpcMonitorCurCfg = {
        .current_phase_a_cfg = &muMpcMeasurementCfg,
        .current_phase_b_cfg = &muMpcMeasurementCfg,
        .current_phase_c_cfg = &muMpcMeasurementCfg,
    };
    static const MuMpcMonitorVoltageConfig muMpcMonitorVolCfg = {
        .voltage_phase_a_cfg  = &muMpcMeasurementCfg,
        .voltage_phase_b_cfg  = &muMpcMeasurementCfg,
        .voltage_phase_c_cfg  = &muMpcMeasurementCfg,
        .voltage_phase_ab_cfg = &muMpcMeasurementCfg,
        .voltage_phase_bc_cfg = &muMpcMeasurementCfg,
        .voltage_phase_ac_cfg = &muMpcMeasurementCfg,
    };
    static const MuMpcMonitorFrequencyConfig muMpcMonitorFreqCfg = {
        .frequency_cfg = {
            .value_source = kMeasurementValueSourceTypeMeasuredValue
        },
    };
    static const MuMpcConfig muMpcCfg = {
        .power_cfg = {
            .power_total_cfg   = {
                .value_source = kMeasurementValueSourceTypeMeasuredValue
            },
            .power_phase_a_cfg = &muMpcMeasurementCfg,
            .power_phase_b_cfg = &muMpcMeasurementCfg,
            .power_phase_c_cfg = &muMpcMeasurementCfg,
        },
        .energy_cfg    = &muMpcMonitorEnergyCfg,
        .current_cfg   = &muMpcMonitorCurCfg,
        .voltage_cfg   = &muMpcMonitorVolCfg,
        .frequency_cfg = &muMpcMonitorFreqCfg
    };
    char altId[128] = {0};
    uint32_t entity_id = 0;

    tlsCrtObj = TlsCertificateParseX509KeyPair(g_eebus_key.crt, strlen(g_eebus_key.crt), g_eebus_key.privkey, strlen(g_eebus_key.privkey));
    if (!tlsCrtObj) {
        ESP_LOGE(TAG, "TlsCertificateParseX509KeyPair failed");
        return -1; 
    }

    serviceCfg = EebusServiceConfigCreate(EEBUS_VENDOR, EEBUS_BRAND, EEBUS_MODEL, EEBUS_SN, EEBUS_TYPE, EEBUS_PORT);
    if (!serviceCfg) {
        ESP_LOGE(TAG, "EebusServiceConfigCreate failed");
        return -2;
    }

    snprintf(altId, sizeof(altId) - 1, "%s-%s-%s", EEBUS_BRAND, EEBUS_MODEL, EEBUS_SN);
    EebusServiceConfigSetAlternateIdentifier(serviceCfg, altId);
    EebusServiceConfigSetAlternateMdnsServiceName(serviceCfg, altId);
    EebusServiceConfigSetRegisterAutoAccept(serviceCfg, false);

    SERVICE_READER_INTERFACE(&serviceReaderObj) = &serviceReaderIf;
    serviceObj = EebusServiceCreate(serviceCfg, "server", tlsCrtObj, SERVICE_READER_OBJECT(&serviceReaderObj));
    if (!serviceObj) {
        ESP_LOGE(TAG, "EebusServiceCreate failed");
        return -3;
    }

    // if (!remote_ski_.empty() && remote_ski_.length() >= 40) {
    //     EEBUS_SERVICE_REGISTER_REMOTE_SKI(serviceObj, remote_ski_.c_str(), true);
    // }

    const char* crt_ski = TLS_CERTIFICATE_GET_SKI(tlsCrtObj);
    memcpy(g_eebus_key.ski, crt_ski, 40);
    ESP_LOGI(TAG, "ski:%s", g_eebus_key.ski);

    devLocalObj = EEBUS_SERVICE_GET_LOCAL_DEVICE(serviceObj);
    if (!devLocalObj) {
        ESP_LOGE(TAG, "GetLocalDevice failed");
        return -4;
    }

    entity_id = VectorGetSize(DEVICE_LOCAL_GET_ENTITIES(devLocalObj));
    entityInvObj = EntityLocalCreate(devLocalObj, kEntityTypeTypeInverter, &entity_id, 1, kHeartbeatTimeoutSeconds);
    if (!entityInvObj) {
        ESP_LOGE(TAG, "EntityLocalCreate inv failed"); 
        return -5;
    }

    CS_LP_LISTENER_INTERFACE(&csLppListenerObj) = &csLppListenerIf;
    csLppUCObj = CsLppUseCaseCreate(entityInvObj, kElectricalConnectionIdType, CS_LP_LISTENER_OBJECT(&csLppListenerObj));
    if (!csLppUCObj) {
        ESP_LOGE(TAG, "CsLppUseCaseCreate failed"); 
        return -6; 
    }

    MU_MPC_LISTENER_INTERFACE(&muMpcListenerObj) = &muMpcListenerIf;
    muMpcUCObj = MuMpcUseCaseCreate(entityInvObj, kElectricalConnectionIdType, &muMpcCfg, MU_MPC_LISTENER_OBJECT(&muMpcListenerObj));
    if (!muMpcUCObj) {
        ESP_LOGE(TAG, "MuMpcUseCaseCreate failed"); 
        return -7; 
    }

    DEVICE_LOCAL_ADD_ENTITY(devLocalObj, entityInvObj);

    entity_id = VectorGetSize(DEVICE_LOCAL_GET_ENTITIES(devLocalObj));
    entitySEAObj = EntityLocalCreate(devLocalObj, kEntityTypeTypeSmartEnergyAppliance, &entity_id, 1, kHeartbeatTimeoutSeconds);
    if (!entitySEAObj) {
        ESP_LOGE(TAG, "EntityLocalCreate sea failed"); 
        return -8;
    }

    CS_LP_LISTENER_INTERFACE(&csLpcListenerObj) = &csLpcListenerIf;
    csLpcUCObj = CsLpcUseCaseCreate(entitySEAObj, kElectricalConnectionIdType, CS_LP_LISTENER_OBJECT(&csLpcListenerObj));
    if (!csLpcUCObj) {
        ESP_LOGE(TAG, "CsLpcUseCaseCreate failed"); 
        return -9; 
    }

    DEVICE_LOCAL_ADD_ENTITY(devLocalObj, entitySEAObj);

    // 判断对端 ski 是否允许接入, ship_node.c->ShipNodeOnWebsocketServerConnectionCallback()->INFO_PROVIDER_IS_WAITING_FOR_TRUST_ALLOWED->eebus_service.c->EebusServiceInterface.is_waiting_for_trust_allowed()
    // 第一层开关针对所有对端 ski, 类似是否处于配对状态, 通过 EEBUS_SERVICE_SET_PAIRING_POSSIBLE 设置, 即赋值 EEBUS_SERVICE(self)->is_pairing_possible
    // 如果为 false, 拒绝任何对端设备接入
    // 如果为 true, 判断第二层开关
    // 第二层开关针对特定对端 ski，通过提前配置 ski 白名单或现场弹窗用户决定的方式设置， 即 eebus_process.c->ServiceReaderInterface.is_waiting_for_trust_allowed(ski) 回调函数返回值
    // 如果为 false, 拒绝该对端 ski 设备接入
    // 如果为 true, 允许接入
    // 当前只判断了第一层开关, 即 EebusServiceInterface.is_waiting_for_trust_allowed() 仅判断 EEBUS_SERVICE(self)->is_pairing_possible 就返回了，后续可以在第一层开关为 true 时，继续通过白名单或弹窗判断第二层开关
    // TODO: 第一层开关不是一直为 true, 窗口期（按键触发、特定时间内等）设置为 true；配对完成（OnShipStateUpdate()->state == kDataExchange 或 OnRemoteSkiConnected()）设置为 false
    EEBUS_SERVICE_SET_PAIRING_POSSIBLE(serviceObj, true); 

    EEBUS_SERVICE_START(serviceObj);

    return 0;
}

EebusError eebus_set_mpc_measurement(eebus_mpc_measurement_data_t ms_data) {
    EebusError err = kEebusErrorOk;
    ScaledValue scale_value = {.scale = kScaleDefault};

    scale_value.value = ms_data.power_total;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcPowerTotal, &scale_value, NULL, NULL);
    scale_value.value = ms_data.power_phase_a;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcPowerPhaseA, &scale_value, NULL, NULL);
    scale_value.value = ms_data.power_phase_b;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcPowerPhaseB, &scale_value, NULL, NULL);
    scale_value.value = ms_data.power_phase_c;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcPowerPhaseC, &scale_value, NULL, NULL);
    scale_value.value = ms_data.current_phase_a;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcCurrentPhaseA, &scale_value, NULL, NULL);
    scale_value.value = ms_data.current_phase_b;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcCurrentPhaseB, &scale_value, NULL, NULL);
    scale_value.value = ms_data.current_phase_c;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcCurrentPhaseC, &scale_value, NULL, NULL);
    scale_value.value = ms_data.voltage_phase_a;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcVoltagePhaseA, &scale_value, NULL, NULL);
    scale_value.value = ms_data.voltage_phase_b;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcVoltagePhaseB, &scale_value, NULL, NULL);
    scale_value.value = ms_data.voltage_phase_c;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcVoltagePhaseC, &scale_value, NULL, NULL);
    scale_value.value = ms_data.voltage_phase_ab;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcVoltagePhaseAb, &scale_value, NULL, NULL);
    scale_value.value = ms_data.voltage_phase_bc;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcVoltagePhaseBc, &scale_value, NULL, NULL);
    scale_value.value = ms_data.voltage_phase_ac;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcVoltagePhaseAc, &scale_value, NULL, NULL);
    scale_value.value = ms_data.frequency;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcFrequency, &scale_value, NULL, NULL);
    scale_value.value = ms_data.energy_consumed;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcEnergyConsumed, &scale_value, NULL, NULL);
    scale_value.value = ms_data.energy_produced;
    err = MuMpcSetMeasurementDataCache(muMpcUCObj, kMpcEnergyProduced, &scale_value, NULL, NULL);

    if (err != kEebusErrorOk) {
        ESP_LOGE(TAG, "MuMpcSetMeasurementDataCache failed:%d", err);
        return err;
    }
    return MuMpcUpdate(muMpcUCObj);
}

void eebus_task_cb(void *pvParameters) {
    int ret = 0;

    gen_self_sign_crt(&g_eebus_key);
    ESP_LOGI(TAG, "%s", g_eebus_key.pubkey);
    ESP_LOGI(TAG, "%s", g_eebus_key.privkey);
    ESP_LOGI(TAG, "%s", g_eebus_key.crt);

    ret = start_inv_service();
    if (ret) {
        ESP_LOGE(TAG, "eebus_process_init failed:%d", ret);
    } else {
        ESP_LOGI(TAG, "eebus_process_init ok");
    }

    while (1) {
        if (kDataExchange == cur_sem_state) {
            // g_ms_data.power_total += 100;
            g_ms_data.power_phase_a += 100;
            g_ms_data.power_phase_b += 100;
            g_ms_data.power_phase_c += 100;

            g_ms_data.energy_consumed += 100;
            g_ms_data.energy_produced += 100;

            g_ms_data.current_phase_a += 100;
            g_ms_data.current_phase_b += 100;
            g_ms_data.current_phase_c += 100;

            g_ms_data.voltage_phase_a += 100;
            g_ms_data.voltage_phase_b += 100;
            g_ms_data.voltage_phase_c += 100;
            g_ms_data.voltage_phase_ab += 100;
            g_ms_data.voltage_phase_bc += 100;
            g_ms_data.voltage_phase_ac += 100;

            g_ms_data.frequency += 100;

            ret = eebus_set_mpc_measurement(g_ms_data);
            if (ret != kEebusErrorOk) {
                ESP_LOGE(TAG, "eebus_set_mpc_measurement failed:%d", ret);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(60000));
    }
}
