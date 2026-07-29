#ifndef PORT_FORWARDER_SERVER_SOCKET_H
#define PORT_FORWARDER_SERVER_SOCKET_H

#include <p101_env/env.h>
#include <p101_fsm/fsm.h>

void socket_create(const struct p101_env *env, struct p101_error *err, void *arg, struct p101_fsm_effect_sink *sink, struct p101_fsm_decision *decision);
void socket_bind(const struct p101_env *env, struct p101_error *err, void *arg, struct p101_fsm_effect_sink *sink, struct p101_fsm_decision *decision);
void socket_listen(const struct p101_env *env, struct p101_error *err, void *arg, struct p101_fsm_effect_sink *sink, struct p101_fsm_decision *decision);
void socket_accept(const struct p101_env *env, struct p101_error *err, void *arg, struct p101_fsm_effect_sink *sink, struct p101_fsm_decision *decision);

#endif    // PORT_FORWARDER_SERVER_SOCKET_H
