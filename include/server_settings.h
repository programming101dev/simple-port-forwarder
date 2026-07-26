#ifndef PORT_FORWARDER_SERVER_SETTINGS_H
#define PORT_FORWARDER_SERVER_SETTINGS_H

struct p101_env;
struct p101_error;
struct settings;

void check_settings(const struct p101_env *env, struct p101_error *err, const struct settings *sets);

#endif    // PORT_FORWARDER_SERVER_SETTINGS_H
