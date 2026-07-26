#ifndef SERVER_SERVER_H
#define SERVER_SERVER_H

#include "settings.h"
#include <p101_env/env.h>

void run_server(const struct p101_env *env, struct p101_error *err, struct settings *sets);

#endif    // SERVER_SERVER_H
