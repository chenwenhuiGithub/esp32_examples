
#include "esp_log.h"
#include "src/common/string_util.h"
#include "cs_lpc_cbs.h"


static const char *TAG = "cs_lpc";

void DestructCsLpc(CsLpListenerObject *self) {

    ESP_LOGI(TAG, "DestructCsLpc");
}

void OnCsLpcPowerLimitReceive(CsLpListenerObject *self, const ScaledValue *power_limit, const EebusDuration *duration, bool is_active) {
    char* power_limit_str = (char*)ScaledValueToString(power_limit);
    char* duration_str = EebusDurationToString(duration);

    ESP_LOGI(TAG, "OnCsLpcPowerLimitReceive, power_limit:%sW duration:%s is_active:%d", power_limit_str, duration_str, is_active);

    StringDelete(power_limit_str);
    StringDelete(duration_str);
}

void OnCsLpcFailsafePowerLimitReceive(CsLpListenerObject *self, const ScaledValue *power_limit) {
    char* power_limit_str = (char*)ScaledValueToString(power_limit);

    ESP_LOGI(TAG, "OnCsLpcFailsafePowerLimitReceive, power_limit:%sW", power_limit_str);
    StringDelete(power_limit_str);
}

void OnCsLpcFailsafeDurationReceive(CsLpListenerObject *self, const DurationType *duration) {
    char* duration_str = EebusDurationToString(duration);

    ESP_LOGI(TAG, "OnCsLpcFailsafeDurationReceive, duration:%s", duration_str);
    StringDelete(duration_str);
}

void OnCsLpcRemoteEgAdded(CsLpListenerObject *self, const EntityAddressType *entity_addr) {

    ESP_LOGI(TAG, "OnCsLpcRemoteEgAdded, device:%s", entity_addr->device);
}

void OnCsLpcRemoteEgRemoved(CsLpListenerObject *self, const EntityAddressType *entity_addr) {

    ESP_LOGI(TAG, "OnCsLpcRemoteEgRemoved, device:%s", entity_addr->device);
}

void OnCsLpcHeartbeatReceive(CsLpListenerObject *self, uint64_t heartbeat_counter) {

    ESP_LOGI(TAG, "OnCsLpcHeartbeatReceive, heartbeat_counter:%llu", heartbeat_counter);
}
