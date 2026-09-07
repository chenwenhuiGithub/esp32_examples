#ifndef CS_LPC_CBS_H_
#define CS_LPC_CBS_H_

#include "src/use_case/api/cs_lp_listener_interface.h"

void DestructCsLpc(CsLpListenerObject *self);
void OnCsLpcPowerLimitReceive(CsLpListenerObject *self, const ScaledValue *power_limit, const DurationType *duration, bool is_active);
void OnCsLpcRemoteEgAdded(CsLpListenerObject *self, const EntityAddressType *entity_addr);
void OnCsLpcRemoteEgRemoved(CsLpListenerObject *self, const EntityAddressType *entity_addr);
void OnCsLpcFailsafePowerLimitReceive(CsLpListenerObject *self, const ScaledValue *power_limit);
void OnCsLpcFailsafeDurationReceive(CsLpListenerObject *self, const DurationType *duration);
void OnCsLpcHeartbeatReceive(CsLpListenerObject *self, uint64_t heartbeat_counter);

#endif
