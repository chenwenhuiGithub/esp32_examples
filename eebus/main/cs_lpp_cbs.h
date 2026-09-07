#ifndef CS_LPP_CBS_H_
#define CS_LPP_CBS_H_

#include "src/use_case/api/cs_lp_listener_interface.h"


void DestructCsLpp(CsLpListenerObject *self);
void OnCsLppPowerLimitReceive(CsLpListenerObject *self, const ScaledValue *power_limit, const DurationType *duration, bool is_active);
void OnCsLppRemoteEgAdded(CsLpListenerObject *self, const EntityAddressType *entity_addr);
void OnCsLppRemoteEgRemoved(CsLpListenerObject *self, const EntityAddressType *entity_addr);
void OnCsLppFailsafePowerLimitReceive(CsLpListenerObject *self, const ScaledValue *power_limit);
void OnCsLppFailsafeDurationReceive(CsLpListenerObject *self, const DurationType *duration);
void OnCsLppHeartbeatReceive(CsLpListenerObject *self, uint64_t heartbeat_counter);

#endif
