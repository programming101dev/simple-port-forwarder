#ifndef SERVER_SERVER_H
#define SERVER_SERVER_H

#include <netinet/in.h>
#include <p101_env/env.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>

struct settings
{
    // cppcheck-suppress unusedStructMember
    int backlog;
    // cppcheck-suppress unusedStructMember
    struct sockaddr_storage addr_in;
    // cppcheck-suppress unusedStructMember
    in_port_t port_in;
    // cppcheck-suppress unusedStructMember
    struct sockaddr_storage addr_out;
    // cppcheck-suppress unusedStructMember
    in_port_t port_out;
    // cppcheck-suppress unusedStructMember
    time_t min_seconds;
    // cppcheck-suppress unusedStructMember
    time_t max_seconds;
    // cppcheck-suppress unusedStructMember
    long min_nanoseconds;
    // cppcheck-suppress unusedStructMember
    long max_nanoseconds;
    // cppcheck-suppress unusedStructMember
    unsigned int min_bytes;
    // cppcheck-suppress unusedStructMember
    unsigned int max_bytes;
    // cppcheck-suppress unusedStructMember
    bool verbose;
    // cppcheck-suppress unusedStructMember
    bool very_verbose;
};

void run_server(const struct p101_env *env, struct p101_error *err, struct settings *sets);

#endif    // SERVER_SERVER_H
