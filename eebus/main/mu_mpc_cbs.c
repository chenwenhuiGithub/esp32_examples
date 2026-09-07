
#include "esp_log.h"
#include "mu_mpc_cbs.h"


static const char *TAG = "mu_mpc";

void DestructMuMpc(MuMpcListenerObject *self) {

    ESP_LOGI(TAG, "DestructMuMpc");
}

void OnMuMpcRemoteMaAdded(MuMpcListenerObject *self, const EntityAddressType *entity_addr) {

    ESP_LOGI(TAG, "OnMuMpcRemoteMaAdded, device:%s", entity_addr->device);
}

void OnMuMpcRemoteMaRemoved(MuMpcListenerObject *self, const EntityAddressType *entity_addr) {

    ESP_LOGI(TAG, "OnMuMpcRemoteMaRemoved, device:%s", entity_addr->device);
}
