#ifndef SERVER_SERVER_H
#define SERVER_SERVER_H

#include <netinet/in.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <stdbool.h>
#include <sys/socket.h>

struct settings
{
    int                     backlog;
    struct sockaddr_storage addr_in;
    in_port_t               port_in;
    struct sockaddr_storage addr_out;
    in_port_t               port_out;
    bool                    verbose;
    bool                    very_verbose;
};

void run_server(const struct p101_env *env, struct p101_error *err, const struct settings *sets);

#endif    // SERVER_SERVER_H
