#include "server.h"
#include <arpa/inet.h>
#include <p101_c/p101_string.h>
#include <p101_posix/arpa/p101_inet.h>
#include <p101_posix/p101_signal.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>

static void setup_signal_handler(const struct p101_env *env, struct p101_error *err);
static void sigint_handler(int signum);
static void sockaddr_to_string(const struct p101_env *env, struct p101_error *err, const struct sockaddr_storage *addr, char *ipstr, socklen_t max_size);

static volatile sig_atomic_t exit_flag = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

void run_server(const struct p101_env *env, struct p101_error *err, const struct settings *sets)
{
    char ip_in_str[INET6_ADDRSTRLEN];
    char ip_out_str[INET6_ADDRSTRLEN];

    P101_TRACE(env);
    sockaddr_to_string(env, err, &sets->addr_in, ip_in_str, INET6_ADDRSTRLEN);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    sockaddr_to_string(env, err, &sets->addr_out, ip_out_str, INET6_ADDRSTRLEN);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    printf("Starting port forwarder %s:%d -> %s:%d\n", ip_in_str, sets->port_in, ip_out_str, sets->port_out);
    setup_signal_handler(env, err);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    return;

error:
    return;
}

static void setup_signal_handler(const struct p101_env *env, struct p101_error *err)
{
    struct sigaction sa;

    P101_TRACE(env);
    p101_memset(env, &sa, 0, sizeof(sa));

#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    sa.sa_handler = sigint_handler;
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    p101_sigaction(env, err, SIGINT, &sa, NULL);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static void sigint_handler(const int signum)
{
    exit_flag = 1;
}

#pragma GCC diagnostic pop

static void sockaddr_to_string(const struct p101_env *env, struct p101_error *err, const struct sockaddr_storage *addr, char *ipstr, socklen_t max_size)
{
    P101_TRACE(env);

    if(addr->ss_family == AF_INET)
    {
        const struct sockaddr_in *addr_in;

        addr_in = (const struct sockaddr_in *)addr;
        p101_inet_ntop(env, err, AF_INET, &addr_in->sin_addr, ipstr, max_size);
    }
    else
    {
        const struct sockaddr_in6 *addr_in6;

        addr_in6 = (const struct sockaddr_in6 *)addr;
        p101_inet_ntop(env, err, AF_INET6, &addr_in6->sin6_addr, ipstr, max_size);
    }
}
