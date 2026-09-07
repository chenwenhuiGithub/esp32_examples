
#include "esp_log.h"
#include "src/common/string_util.h"
#include "cs_lpp_cbs.h"


static const char *TAG = "cs_lpp";

void DestructCsLpp(CsLpListenerObject *self) {

    ESP_LOGI(TAG, "DestructCsLpp");
}

void OnCsLppPowerLimitReceive(CsLpListenerObject *self, const ScaledValue *power_limit, const EebusDuration *duration, bool is_active) {
    char* power_limit_str = (char*)ScaledValueToString(power_limit);
    char* duration_str = EebusDurationToString(duration);

    ESP_LOGI(TAG, "OnCsLppPowerLimitReceive, power_limit:%sW duration:%s is_active:%d", power_limit_str, duration_str, is_active);

    StringDelete(power_limit_str);
    StringDelete(duration_str);
}

void OnCsLppFailsafePowerLimitReceive(CsLpListenerObject *self, const ScaledValue *power_limit) {
    char* power_limit_str = (char*)ScaledValueToString(power_limit);

    ESP_LOGI(TAG, "OnCsLppFailsafePowerLimitReceive, power_limit:%sW", power_limit_str);
    StringDelete(power_limit_str);
}

void OnCsLppFailsafeDurationReceive(CsLpListenerObject *self, const DurationType *duration) {
    char* duration_str = EebusDurationToString(duration);

    ESP_LOGI(TAG, "OnCsLppFailsafeDurationReceive, duration:%s", duration_str);
    StringDelete(duration_str);
}

void OnCsLppRemoteEgAdded(CsLpListenerObject *self, const EntityAddressType *entity_addr) {

    ESP_LOGI(TAG, "OnCsLppRemoteEgAdded, device:%s", entity_addr->device);
}

void OnCsLppRemoteEgRemoved(CsLpListenerObject *self, const EntityAddressType *entity_addr) {

    ESP_LOGI(TAG, "OnCsLppRemoteEgRemoved, device:%s", entity_addr->device);
}

void OnCsLppHeartbeatReceive(CsLpListenerObject *self, uint64_t heartbeat_counter) {

    ESP_LOGI(TAG, "OnCsLppHeartbeatReceive, heartbeat_counter:%llu", heartbeat_counter);
}
