#ifndef PORT_FORWARDER_SERVER_SOCKET_H
#define PORT_FORWARDER_SERVER_SOCKET_H

#include <p101_env/env.h>
#include <p101_fsm/fsm.h>

p101_fsm_state_t socket_create(const struct p101_env *env, struct p101_error *err, void *arg);
p101_fsm_state_t socket_bind(const struct p101_env *env, struct p101_error *err, void *arg);
p101_fsm_state_t socket_listen(const struct p101_env *env, struct p101_error *err, void *arg);
p101_fsm_state_t socket_accept(const struct p101_env *env, struct p101_error *err, void *arg);

#endif    // PORT_FORWARDER_SERVER_SOCKET_H
