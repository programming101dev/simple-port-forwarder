#include "server.h"
#include <arpa/inet.h>
#include <p101_c/p101_string.h>
#include <p101_fsm/fsm.h>
#include <p101_posix/arpa/p101_inet.h>
#include <p101_posix/p101_signal.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>

static void             setup_signal_handler(const struct p101_env *env, struct p101_error *err);
static void             sigint_handler(int signum);
static void             sockaddr_to_string(const struct p101_env *env, struct p101_error *err, const struct sockaddr_storage *addr, char *ipstr, socklen_t max_size);
static p101_fsm_state_t socket_create(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t socket_bind(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t socket_accept(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t handle_connection(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t handle_error(const struct p101_env *env, struct p101_error *err, void *arg);

static volatile sig_atomic_t exit_flag = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

enum server_states
{
    SOCKET = P101_FSM_USER_START,    // 2
    BIND,
    LISTEN,
    ACCEPT,
    HANDLE,
    ERROR,
};

struct server_data
{
    const struct settings *sets;
};

void run_server(const struct p101_env *env, struct p101_error *err, const struct settings *sets)
{
    char                              ip_in_str[INET6_ADDRSTRLEN];
    char                              ip_out_str[INET6_ADDRSTRLEN];
    struct p101_error                *fsm_error;
    struct p101_env                  *fsm_env;
    struct p101_fsm_info             *fsm;
    p101_fsm_state_t                  from_state;
    p101_fsm_state_t                  to_state;
    static struct p101_fsm_transition transitions[] = {
        {P101_FSM_INIT, SOCKET,        socket_create    },
        {SOCKET,        BIND,          socket_bind      },
        {SOCKET,        P101_FSM_EXIT, NULL             },
        {SOCKET,        ERROR,         handle_error     },
        {BIND,          ACCEPT,        socket_accept    },
        {BIND,          P101_FSM_EXIT, NULL             },
        {BIND,          ERROR,         handle_error     },
        {ACCEPT,        HANDLE,        handle_connection},
        {ACCEPT,        P101_FSM_EXIT, NULL             },
        {ACCEPT,        ERROR,         handle_error     },
        {HANDLE,        ACCEPT,        socket_accept    },
        {HANDLE,        P101_FSM_EXIT, NULL             },
        {HANDLE,        ERROR,         handle_error     },
        {ERROR,         P101_FSM_EXIT, NULL             }
    };
    struct server_data data;

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

    fsm_error = p101_error_create(false);
    fsm_env   = p101_env_create(err, true, NULL);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    if(sets->very_verbose)
    {
        p101_env_set_tracer(fsm_env, p101_env_default_tracer);
    }

    fsm = p101_fsm_info_create(env, err, "test-fsm", fsm_env, fsm_error, NULL);

    if(sets->very_verbose)
    {
        p101_fsm_info_set_bad_change_state_notifier(fsm, p101_fsm_info_default_bad_change_state_notifier);
        p101_fsm_info_set_will_change_state_notifier(fsm, p101_fsm_info_default_will_change_state_notifier);
        p101_fsm_info_set_did_change_state_notifier(fsm, p101_fsm_info_default_did_change_state_notifier);
    }

    data.sets = sets;
    p101_fsm_run(fsm, &from_state, &to_state, &data, transitions);
    p101_fsm_info_destroy(env, &fsm);

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

static p101_fsm_state_t socket_create(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;

    P101_TRACE(env);
    data = arg;

    if(data->sets->verbose)
    {
        printf("socket");
    }

    P101_ERROR_RAISE_USER(err, "socket", 0);

    return P101_FSM_EXIT;
}

static p101_fsm_state_t socket_bind(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;

    P101_TRACE(env);
    data = arg;

    if(data->sets->verbose)
    {
        printf("bind");
    }

    P101_ERROR_RAISE_USER(err, "bind", 0);

    return P101_FSM_EXIT;
}

static p101_fsm_state_t socket_accept(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;

    P101_TRACE(env);
    data = arg;

    if(data->sets->verbose)
    {
        printf("accept");
    }

    P101_ERROR_RAISE_USER(err, "accept", 0);

    return P101_FSM_EXIT;
}

static p101_fsm_state_t handle_connection(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;

    P101_TRACE(env);
    data = arg;

    if(data->sets->verbose)
    {
        printf("handle_connection");
    }

    P101_ERROR_RAISE_USER(err, "handle_connection", 0);

    return P101_FSM_EXIT;
}

static p101_fsm_state_t handle_error(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;

    P101_TRACE(env);
    data = arg;

    if(data->sets->verbose)
    {
        printf("handle_error");
    }

    P101_ERROR_RAISE_USER(err, "handle_error", 0);

    return P101_FSM_EXIT;
}
