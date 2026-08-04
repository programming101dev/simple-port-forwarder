#ifndef PORT_FORWARDER_CLI_H
#define PORT_FORWARDER_CLI_H

#include "settings.h"
#include <p101_env/env.h>
#include <stdbool.h>

struct arguments
{
    char *backlog;
    char *ip_address_in;
    char *port_in;
    char *ip_address_out;
    char *port_out;
    char *min_seconds;
    char *max_seconds;
    char *min_nanoseconds;
    char *max_nanoseconds;
    char *min_bytes;
    char *max_bytes;
    bool  verbose;
    bool  very_verbose;
    bool  show_help;
};

void parse_arguments(const struct p101_env *env, struct p101_error *err, int argc, char *argv[], struct arguments *args);
void check_arguments(const struct p101_env *env, struct p101_error *err, const struct arguments *args);
void convert_arguments(const struct p101_env *env, struct p101_error *err, const struct arguments *args, struct settings *sets);
void usage(const struct p101_env *env, struct p101_error *err, const char *program_name, int exit_code, const char *message);

#endif    // PORT_FORWARDER_CLI_H
