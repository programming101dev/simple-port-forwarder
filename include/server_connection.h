#ifndef PORT_FORWARDER_SERVER_CONNECTION_H
#define PORT_FORWARDER_SERVER_CONNECTION_H

#include <p101_env/env.h>
#include <p101_fsm/fsm.h>

p101_fsm_state_t handle_connection(const struct p101_env *env, struct p101_error *err, void *arg);
p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *arg);

#endif    // PORT_FORWARDER_SERVER_CONNECTION_H
