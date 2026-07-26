#ifndef PORT_FORWARDER_SERVER_STATE_H
#define PORT_FORWARDER_SERVER_STATE_H

#include <p101_c/p101_stdatomic.h>
#include <p101_fsm/fsm.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>

struct p101_env;
struct settings;

struct server_data
{
    struct settings *sets;
    int              server_socket;
    int              client_socket;
    int              forward_socket;
};

struct copy_data
{
    const struct p101_env *env;
    const struct settings *sets;
    int                    to_fd;
    int                    from_fd;
};

enum server_states
{
    SOCKET = P101_FSM_USER_START,
    BIND,
    LISTEN,
    ACCEPT,
    HANDLE,
    CLEANUP,
};

bool             server_exit_requested(void);
void             server_request_exit(void);
pthread_mutex_t *server_lock(void);
pthread_cond_t  *server_cond(void);
void             server_active_threads_reset(const struct p101_env *env);
unsigned int     server_active_threads_load(const struct p101_env *env);
void             server_active_threads_increment(const struct p101_env *env);
void             server_active_threads_decrement(const struct p101_env *env);

#endif    // PORT_FORWARDER_SERVER_STATE_H
