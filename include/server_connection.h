#ifndef PORT_FORWARDER_SERVER_CONNECTION_H
#define PORT_FORWARDER_SERVER_CONNECTION_H

#include <p101_env/env.h>
#include <p101_fsm/fsm.h>
#include <stdbool.h>

void handle_connection(const struct p101_env *env, struct p101_error *err, void *arg, struct p101_fsm_effect_sink *sink, struct p101_fsm_decision *decision);
void cleanup(const struct p101_env *env, struct p101_error *err, void *arg, struct p101_fsm_effect_sink *sink, struct p101_fsm_decision *decision);

struct settings;

bool server_copy_once_for_test(const struct p101_env *env, struct p101_error *err, int to_fd, int from_fd, const struct settings *sets);
bool server_connection_error_is_local_for_test(const struct p101_error *err);

#endif    // PORT_FORWARDER_SERVER_CONNECTION_H
