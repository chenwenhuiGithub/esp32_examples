#ifndef MU_MPC_CBS_H_
#define MU_MPC_CBS_H_

#include "src/use_case/api/mu_mpc_listener_interface.h"


void DestructMuMpc(MuMpcListenerObject *self);
void OnMuMpcRemoteMaAdded(MuMpcListenerObject *self, const EntityAddressType *entity_addr);
void OnMuMpcRemoteMaRemoved(MuMpcListenerObject *self, const EntityAddressType *entity_addr);

#endif
