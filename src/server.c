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
#include <p101_unix/p101_stdlib.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/socket.h>

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

static void             check_settings(const struct p101_env *env, struct p101_error *err, const struct settings *sets);
static void             setup_signal_handler(const struct p101_env *env, struct p101_error *err);
static void             sigint_handler(int signum);
static p101_fsm_state_t socket_create(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t socket_bind(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t socket_listen(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t socket_accept(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t handle_connection(const struct p101_env *env, struct p101_error *err, void *arg);
static void             start_copy_thread(const struct p101_env *env, struct p101_error *err, pthread_t *forwarder_thread, struct copy_data *data, const struct settings *sets, int from_socket, int to_socket);
static void            *copy_handler(void *arg);
static bool             copy(const struct p101_env *env, struct p101_error *err, int to_fd, int from_fd, const struct settings *sets);
static void             delay(const struct p101_env *env, struct p101_error *err, time_t min_seconds, time_t max_seconds, long min_nanoseconds, long max_nanoseconds);
static long             generate_random_long(const struct p101_env *env, long min, long max);
static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *arg);

static volatile sig_atomic_t exit_flag      = 0;                            // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static pthread_mutex_t       lock           = PTHREAD_MUTEX_INITIALIZER;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static pthread_cond_t        cond           = PTHREAD_COND_INITIALIZER;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static atomic_uint           active_threads = 0;                            // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

#ifndef BUFFER_LEN
    #define BUFFER_LEN ((size_t)10240 * (size_t)10)
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
    p101_fsm_run(fsm, &from_state, &to_state, &data, transitions, sizeof(transitions));
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

// TODO: actually add this to the FSM
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

    p101_setsockopt(env, err, data->server_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if(p101_error_has_error(err))
    {
        goto error;
    }

    p101_bind(env, err, data->server_socket, (struct sockaddr *)&data->sets->addr_in, addr_len);

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
    pthread_t           from_forwarder;
    struct copy_data    from_data;
    pthread_t           to_forwarder;
    struct copy_data    to_data;

    P101_TRACE(env);
    printf("Handing connection\n");
    data                 = (struct server_data *)arg;
    data->forward_socket = p101_socket(env, err, data->sets->addr_in.ss_family, SOCK_STREAM, 0);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    net_port = htons(data->sets->port_out);

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

    printf("Connecting to server\n");
    p101_connect(env, err, data->forward_socket, (struct sockaddr *)&data->sets->addr_out, addr_len);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    printf("Connected to server\n");
    start_copy_thread(env, err, &from_forwarder, &from_data, data->sets, data->forward_socket, data->client_socket);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    start_copy_thread(env, err, &to_forwarder, &to_data, data->sets, data->client_socket, data->forward_socket);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    // wait for a thread to signal the condition
    pthread_mutex_lock(&lock);

    //    printf("active threads = %u\n", atomic_load(&active_threads));

    while(atomic_load(&active_threads) > 1)
    {
        printf("active threads = %u\n", atomic_load(&active_threads));
        printf("waiting on condition\n");
        pthread_cond_wait(&cond, &lock);
        printf("condition done\n");
    }

    pthread_mutex_unlock(&lock);
    printf("closing %d\n", data->client_socket);
    p101_close(env, err, data->client_socket);
    printf("closing %d\n", data->forward_socket);
    p101_close(env, err, data->forward_socket);

    // wait for a thread to finish
    p101_pthread_join(env, err, from_forwarder, NULL);
    p101_pthread_join(env, err, to_forwarder, NULL);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    next_state = ACCEPT;
    goto done;

error:
    next_state = CLEANUP;

done:
    printf("Connection handled\n");

    return next_state;
}

static void start_copy_thread(const struct p101_env *env, struct p101_error *err, pthread_t *forwarder_thread, struct copy_data *data, const struct settings *sets, int from_socket, int to_socket)
{
    data->env     = env;
    data->err     = err;
    data->sets    = sets;
    data->from_fd = from_socket;
    data->to_fd   = to_socket;

    atomic_fetch_add(&active_threads, 1);
    p101_pthread_create(env, err, forwarder_thread, NULL, copy_handler, data);

    // TODO: handle if pthread_create fails
}

static void *copy_handler(void *arg)
{
    struct copy_data *data;
    bool              closed;

    data = (struct copy_data *)arg;

    do
    {
        closed = copy(data->env, data->err, data->to_fd, data->from_fd, data->sets);

        if(p101_error_has_error(data->err))
        {
            goto done;
        }

        printf("closed %d -> %d?: %d\n", data->from_fd, data->to_fd, closed);
    } while(!(closed));

done:
    printf("Ending thread\n");
    atomic_fetch_sub(&active_threads, 1);
    pthread_mutex_lock(&lock);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);

    return NULL;
}

static bool copy(const struct p101_env *env, struct p101_error *err, int to_fd, int from_fd, const struct settings *sets)
{
    uint8_t buffer[BUFFER_LEN];
    ssize_t bytes_read;
    bool    closed;

    closed = false;
    printf("Reading from %d to send to %d\n", from_fd, to_fd);
    bytes_read = p101_read(env, err, from_fd, buffer, BUFFER_LEN);
    printf("Read %zd from %d to send to %d\n", bytes_read, from_fd, to_fd);

    if(p101_error_has_error(err))
    {
        if(p101_error_is_errno(err, EBADF))
        {
            p101_error_reset(err);
            closed = true;
        }

        goto done;
    }

    if(bytes_read == 0)
    {
        closed = true;
    }
    else
    {
        size_t bytes_remaining;
        size_t pos;

        bytes_remaining = (size_t)bytes_read;
        pos             = 0;

        do
        {
            size_t  bytes_to_write;
            ssize_t bytes_written;

            if(sets->min_bytes == 0)
            {
                bytes_to_write = bytes_remaining;
            }
            else
            {
                if(sets->min_bytes == sets->max_bytes)
                {
                    bytes_to_write = sets->min_bytes;
                }
                else
                {
                    bytes_to_write = p101_arc4random_uniform(env, (uint32_t)(sets->max_bytes - sets->min_bytes + 1)) + sets->min_bytes;
                }

                if(bytes_to_write > bytes_remaining)
                {
                    bytes_to_write = bytes_remaining;
                }
            }

            // #pragma GCC diagnostic push
            // #pragma GCC diagnostic ignored "-Wunsafe-buffer-usage"
            bytes_written = p101_write(env, err, to_fd, &buffer[pos], bytes_to_write);
            // #pragma GCC diagnostic pop

            if(p101_error_has_error(err))
            {
                goto done;
            }

            // TODO: if verbose
            /*
            printf("\n----\n");
            fflush(stdout);
            p101_write(env, err, STDOUT_FILENO, &buffer[pos], (size_t)bytes_written);
            fflush(stdout);
            printf("\n----\n");
            */
            if(p101_error_has_error(err))
            {
                goto done;
            }

            bytes_remaining -= (size_t)bytes_written;
            pos += (size_t)bytes_written;
            delay(env, err, sets->min_seconds, sets->max_seconds, sets->min_nanoseconds, sets->max_nanoseconds);

            if(p101_error_has_error(err))
            {
                goto done;
            }
        } while(bytes_remaining > 0);
    }

done:
    return closed;
}

static void delay(const struct p101_env *env, struct p101_error *err, time_t min_seconds, time_t max_seconds, long min_nanoseconds, long max_nanoseconds)
{
    struct timespec tim;

    if(min_seconds == max_seconds && min_nanoseconds == max_nanoseconds)
    {
        tim.tv_sec  = min_seconds;
        tim.tv_nsec = min_nanoseconds;
    }
    else
    {
        tim.tv_sec  = min_seconds;
        tim.tv_nsec = generate_random_long(env, min_nanoseconds, max_nanoseconds);
    }

    p101_nanosleep(env, err, &tim, NULL);
}

static long generate_random_long(const struct p101_env *env, long min, long max)
{
    long num;

    num = 0;

    for(size_t i = 0; i < sizeof(long); i += sizeof(uint32_t))
    {
        num = (num << 32) | p101_arc4random(env);    // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }

    return min + num % (max - min + 1);
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
        printf("closing %d\n", data->server_socket);
        p101_close(env, err, data->server_socket);
        data->server_socket = -1;
    }

    return P101_FSM_EXIT;
}
