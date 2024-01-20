#include "server.h"
#include "convert.h"
#include <arpa/inet.h>
#include <p101_c/p101_string.h>
#include <p101_fsm/fsm.h>
#include <p101_posix/p101_pthread.h>
#include <p101_posix/p101_signal.h>
#include <p101_posix/p101_time.h>
#include <p101_posix/p101_unistd.h>
#include <p101_posix/sys/p101_socket.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>

static void             check_settings(const struct p101_env *env, struct p101_error *err, const struct settings *sets);
static void             setup_signal_handler(const struct p101_env *env, struct p101_error *err);
static void             sigint_handler(int signum);
static p101_fsm_state_t socket_create(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t socket_bind(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t socket_listen(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t socket_accept(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t handle_connection(const struct p101_env *env, struct p101_error *err, void *arg);
static void            *copy_handler(void *arg);
static ssize_t          copy(const struct p101_env *env, struct p101_error *err, int to_fd, int from_fd, const struct settings *sets);
static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *arg);

static volatile sig_atomic_t exit_flag = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

#ifndef BUFFER_LEN
    #define BUFFER_LEN ((size_t)1024 * (size_t)10)
#endif

enum server_states
{
    SOCKET = P101_FSM_USER_START,    // 2
    BIND,
    LISTEN,
    ACCEPT,
    HANDLE,
    CLEANUP,
};

struct server_data
{
    struct settings *sets;
    int              server_socket;
    int              client_socket;
    int              forward_socket;
};

struct copy_data
{
    struct p101_error     *err;
    const struct p101_env *env;
    const struct settings *sets;
    int                    to_fd;
    int                    from_fd;
};

void run_server(const struct p101_env *env, struct p101_error *err, struct settings *sets)
{
    char                              ip_in_str[INET6_ADDRSTRLEN];
    char                              ip_out_str[INET6_ADDRSTRLEN];
    struct p101_error                *fsm_err;
    struct p101_env                  *fsm_env;
    struct p101_fsm_info             *fsm;
    p101_fsm_state_t                  from_state;
    p101_fsm_state_t                  to_state;
    static struct p101_fsm_transition transitions[] = {
        {P101_FSM_INIT, SOCKET,        socket_create    },
        {SOCKET,        BIND,          socket_bind      },
        {SOCKET,        CLEANUP,       cleanup          },
        {BIND,          LISTEN,        socket_listen    },
        {BIND,          CLEANUP,       cleanup          },
        {LISTEN,        ACCEPT,        socket_accept    },
        {LISTEN,        CLEANUP,       cleanup          },
        {ACCEPT,        HANDLE,        handle_connection},
        {ACCEPT,        CLEANUP,       cleanup          },
        {HANDLE,        ACCEPT,        socket_accept    },
        {HANDLE,        CLEANUP,       cleanup          },
        {CLEANUP,       P101_FSM_EXIT, NULL             }
    };
    struct server_data data;

    P101_TRACE(env);
    check_settings(env, err, sets);

    if(p101_error_has_error(err))
    {
        goto error;
    }

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

    fsm_err = p101_error_create(false);
    fsm_env = p101_env_create(err, true, NULL);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    if(sets->very_verbose)
    {
        p101_env_set_tracer(fsm_env, p101_env_default_tracer);
    }

    fsm = p101_fsm_info_create(env, err, "test-fsm", fsm_env, fsm_err, NULL);

    if(sets->very_verbose)
    {
        p101_fsm_info_set_bad_change_state_notifier(fsm, p101_fsm_info_default_bad_change_state_notifier);
        p101_fsm_info_set_will_change_state_notifier(fsm, p101_fsm_info_default_will_change_state_notifier);
        p101_fsm_info_set_did_change_state_notifier(fsm, p101_fsm_info_default_did_change_state_notifier);
    }

    data.sets = sets;
    p101_fsm_run(fsm, &from_state, &to_state, &data, transitions);
    p101_fsm_info_destroy(env, &fsm);

    if(p101_error_has_error(fsm_err))
    {
        goto error;
    }

    if(p101_error_has_error(err))
    {
        goto error;
    }

    return;

error:
    return;
}

static void check_settings(const struct p101_env *env, struct p101_error *err, const struct settings *sets)
{
    P101_TRACE(env);

    if(sets->min_seconds > sets->max_seconds)
    {
        P101_ERROR_RAISE_USER(err, "min-seconds must be <= max-seconds", 1);
        goto done;
    }

    if(sets->min_nanoseconds > sets->max_nanoseconds)
    {
        P101_ERROR_RAISE_USER(err, "min-nanoseconds must be <= max-nanoseconds", 2);
        goto done;
    }

    if(sets->min_bytes > sets->max_bytes)
    {
        P101_ERROR_RAISE_USER(err, "min-bytes must be <= max-bytes", 3);
        goto done;
    }

done:
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

static p101_fsm_state_t socket_create(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;
    p101_fsm_state_t    next_state;

    P101_TRACE(env);
    data                = (struct server_data *)arg;
    data->server_socket = p101_socket(env, err, data->sets->addr_in.ss_family, SOCK_STREAM, 0);

    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }
    else
    {
        next_state = BIND;
    }

    return next_state;
}

static p101_fsm_state_t socket_bind(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;
    socklen_t           addr_len;
    in_port_t           net_port;
    p101_fsm_state_t    next_state;

    P101_TRACE(env);
    data     = (struct server_data *)arg;
    net_port = htons(data->sets->port_in);

    if(data->sets->addr_in.ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)&data->sets->addr_in;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
    }
    else if(data->sets->addr_in.ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)&data->sets->addr_in;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
    }
    else
    {
        P101_ERROR_RAISE_USER(err, "Internal error: addr->ss_family must be AF_INET or AF_INET6", 1);
        goto error;
    }

    if(p101_error_has_no_error(err))
    {
        p101_bind(env, err, data->server_socket, (struct sockaddr *)&data->sets->addr_in, addr_len);
    }

    if(p101_error_has_error(err))
    {
        goto error;
    }

    next_state = LISTEN;
    goto done;

error:
    next_state = CLEANUP;

done:
    return next_state;
}

static p101_fsm_state_t socket_listen(const struct p101_env *env, struct p101_error *err, void *arg)
{
    const struct server_data *data;
    p101_fsm_state_t          next_state;

    P101_TRACE(env);
    data = (struct server_data *)arg;
    p101_listen(env, err, data->server_socket, data->sets->backlog);

    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }
    else
    {
        next_state = ACCEPT;
    }

    return next_state;
}

static p101_fsm_state_t socket_accept(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;
    p101_fsm_state_t    next_state;

    P101_TRACE(env);
    data                = (struct server_data *)arg;
    data->client_socket = p101_accept(env, err, data->server_socket, NULL, 0);

    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }
    else
    {
        next_state = HANDLE;
    }

    return next_state;
}

static p101_fsm_state_t handle_connection(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;
    p101_fsm_state_t    next_state;
    socklen_t           addr_len;
    in_port_t           net_port;

    P101_TRACE(env);
    data                 = (struct server_data *)arg;
    data->forward_socket = p101_socket(env, err, data->sets->addr_in.ss_family, SOCK_STREAM, 0);
    net_port             = htons(data->sets->port_out);

    if(data->sets->addr_in.ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)&data->sets->addr_out;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
    }
    else if(data->sets->addr_in.ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)&data->sets->addr_out;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
    }
    else
    {
        P101_ERROR_RAISE_USER(err, "Internal error: addr->ss_family must be AF_INET or AF_INET6", 1);
        goto error;
    }

    if(p101_error_has_no_error(err))
    {
        p101_connect(env, err, data->forward_socket, (struct sockaddr *)&data->sets->addr_out, addr_len);
    }

    if(p101_error_has_no_error(err))
    {
        struct copy_data to_forwarder_data;
        pthread_t        to_forwarder;
        struct copy_data from_forwarder_data;
        pthread_t        from_forwarder;

        to_forwarder_data.env     = env;
        to_forwarder_data.err     = err;
        to_forwarder_data.sets    = data->sets;
        to_forwarder_data.from_fd = data->client_socket;
        to_forwarder_data.to_fd   = data->forward_socket;
        p101_pthread_create(env, err, &to_forwarder, NULL, copy_handler, &to_forwarder_data);

        if(p101_error_has_error(err))
        {
            goto error;
        }

        from_forwarder_data.env     = env;
        from_forwarder_data.err     = err;
        from_forwarder_data.sets    = data->sets;
        from_forwarder_data.from_fd = data->forward_socket;
        from_forwarder_data.to_fd   = data->client_socket;
        p101_pthread_create(env, err, &from_forwarder, NULL, copy_handler, &from_forwarder_data);

        if(p101_error_has_error(err))
        {
            goto error;
        }

        // wait for the threads to finish
        p101_pthread_join(env, err, to_forwarder, NULL);
        p101_pthread_join(env, err, from_forwarder, NULL);
    }

    if(p101_error_has_error(err))
    {
        goto error;
    }

    next_state = ACCEPT;
    goto done;

error:
    next_state = CLEANUP;

done:
    return next_state;
}

static void *copy_handler(void *arg)
{
    struct copy_data *data;

    data = (struct copy_data *)arg;
    copy(data->env, data->err, data->to_fd, data->from_fd, data->sets);

    return NULL;
}

static ssize_t copy(const struct p101_env *env, struct p101_error *err, int to_fd, int from_fd, const struct settings *sets)
{
    uint8_t buffer[BUFFER_LEN];
    ssize_t bytes_read;

    bytes_read = p101_read(env, err, from_fd, buffer, BUFFER_LEN);

    if(p101_error_has_no_error(err))
    {
        if(bytes_read == 0)
        {
            p101_close(env, err, to_fd);
        }
        else
        {
            size_t bytes_remaining;
            size_t pos;

            bytes_remaining = (size_t)bytes_read;
            pos             = 0;

            do
            {
                size_t          bytes_to_write;
                ssize_t         bytes_written;
                struct timespec tim;

                if(sets->min_bytes > 0)
                {
                    // TODO: calculate this as a random number
                    bytes_to_write = sets->min_bytes;
                }
                else
                {
                    bytes_to_write = bytes_remaining;
                }

                bytes_written = p101_write(env, err, to_fd, &buffer[pos], bytes_to_write);

                if(p101_error_has_error(err))
                {
                    goto done;
                }

                p101_write(env, err, STDOUT_FILENO, &buffer[pos], (size_t)bytes_written);
                bytes_remaining -= (size_t)bytes_written;
                pos += (size_t)bytes_written;
                // TODO: random time
                tim.tv_sec  = sets->min_seconds;
                tim.tv_nsec = sets->min_nanoseconds;
                p101_nanosleep(env, err, &tim, NULL);

                if(p101_error_has_error(err))
                {
                    goto done;
                }
            } while(bytes_remaining > 0);
        }
    }

done:
    return bytes_read;
}

static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *arg)
{
    struct server_data *data;

    P101_TRACE(env);
    data = (struct server_data *)arg;

    // TODO close client socket too
    // TODO: is this -1 at the start?
    if(data->server_socket != -1)
    {
        p101_close(env, err, data->server_socket);
        data->server_socket = -1;
    }

    return P101_FSM_EXIT;
}
