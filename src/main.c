/*
 * This code is licensed under the Attribution-NonCommercial-NoDerivatives 4.0
 * International license.
 *
 * Author: D'Arcy Smith (ds@programming101.dev)
 *
 * You are free to:
 *   - Share: Copy and redistribute the material in any medium or format.
 *   - Under the following terms:
 *       - Attribution: You must give appropriate credit, provide a link to the
 * license, and indicate if changes were made.
 *       - NonCommercial: You may not use the material for commercial purposes.
 *       - NoDerivatives: If you remix, transform, or build upon the material,
 * you may not distribute the modified material.
 *
 * For more details, please refer to the full license text at:
 * https://creativecommons.org/licenses/by-nc-nd/4.0/
 */

#include "convert.h"
#include "server.h"
#include <p101_c/p101_string.h>
#include <p101_posix/p101_signal.h>
#include <p101_posix/p101_unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

struct arguments
{
    char *backlog;
    char *ip_address_in;
    char *port_in;
    char *ip_address_out;
    char *port_out;
    bool  verbose;
    bool  very_verbose;
};

static void           parse_arguments(const struct p101_env *env, int argc, char *argv[], struct arguments *args);
static void           check_arguments(const struct p101_env *env, const char *binary_name, const struct arguments *args);
static void           convert_arguments(const struct p101_env *env, struct p101_error *err, const struct arguments *args, struct settings *sets);
_Noreturn static void usage(const struct p101_env *env, const char *program_name, int exit_code, const char *message);

#define UNKNOWN_OPTION_MESSAGE_LEN 24

int main(int argc, char *argv[])
{
    struct p101_error *err;
    struct p101_env   *env;
    struct arguments   args = {0};
    struct settings    sets = {0};
    int                exit_code;

    err = p101_error_create(false);
    env = p101_env_create(err, true, NULL);
    parse_arguments(env, argc, argv, &args);

    if(args.verbose || args.very_verbose)
    {
        p101_env_set_tracer(env, p101_env_default_tracer);
    }

    check_arguments(env, argv[0], &args);
    convert_arguments(env, err, &args, &sets);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    run_server(env, err, &sets);

    if(p101_error_has_error(err))
    {
        goto error;
    }

    exit_code = EXIT_SUCCESS;
    goto done;

error:
    fprintf(stderr, "Error: %s\n", p101_error_get_message(err));
    exit_code = EXIT_FAILURE;

done:
    p101_error_reset(err);
    free(env);
    free(err);

    return exit_code;
}

static void parse_arguments(const struct p101_env *env, int argc, char *argv[], struct arguments *args)
{
    int opt;

    P101_TRACE(env);
    opterr = 0;

    while((opt = p101_getopt(env, argc, argv, "hvVb:a:p:A:P:")) != -1)
    {
        switch(opt)
        {
            case 'v':
            {
                args->verbose = true;
                break;
            }
            case 'V':
            {
                args->very_verbose = true;
                break;
            }
            case 'b':
            {
                args->backlog = optarg;
                break;
            }
            case 'a':
            {
                args->ip_address_in = optarg;
                break;
            }
            case 'p':
            {
                args->port_in = optarg;
                break;
            }
            case 'A':
            {
                args->ip_address_out = optarg;
                break;
            }
            case 'P':
            {
                args->port_out = optarg;
                break;
            }
            case 'h':
            {
                usage(env, argv[0], EXIT_SUCCESS, NULL);
            }
            case '?':
            {
                // TODO: this could be better run with -b (no arg)
                // it says unknown flag -b - but -b is known, it is just missing the value
                char message[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                usage(env, argv[0], EXIT_FAILURE, message);
            }
            default:
            {
                usage(env, argv[0], EXIT_FAILURE, NULL);
            }
        }
    }

    if(optind > argc)
    {
        usage(env, argv[0], EXIT_FAILURE, "Error: Too many arguments.");
    }
}

static void check_arguments(const struct p101_env *env, const char *binary_name, const struct arguments *args)
{
    P101_TRACE(env);

    if(args->ip_address_in == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The listening ip address is required.");
    }

    if(args->port_in == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The listening port is required.");
    }

    if(args->ip_address_out == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The forwarding ip address is required.");
    }

    if(args->port_out == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The forwarding port is required.");
    }

    if(args->backlog == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The backlog is required.");
    }
}

static void convert_arguments(const struct p101_env *env, struct p101_error *error, const struct arguments *args, struct settings *sets)
{
    P101_TRACE(env);
    sets->verbose      = args->verbose;
    sets->very_verbose = args->very_verbose;
    convert_address(env, error, args->ip_address_in, &sets->addr_in);

    if(p101_error_has_error(error))
    {
        goto error;
    }

    convert_address(env, error, args->ip_address_out, &sets->addr_out);

    if(p101_error_has_error(error))
    {
        goto error;
    }

    sets->port_in = parse_in_port_t(env, error, args->port_in);

    if(p101_error_has_error(error))
    {
        goto error;
    }

    sets->port_out = parse_in_port_t(env, error, args->port_out);

    if(p101_error_has_error(error))
    {
        goto error;
    }

    sets->backlog = parse_positive_int(env, error, args->backlog);

    if(p101_error_has_error(error))
    {
        goto error;
    }

    goto done;

error:
done:
    return;
}

_Noreturn static void usage(const struct p101_env *env, const char *program_name, int exit_code, const char *message)
{
    P101_TRACE(env);

    if(message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr,
            "Usage: %s [-h] [-v] [-V] -b <backlog> -a <ip address> -p <port> -A "
            "<ip address> -P <port>\n",
            program_name);
    fputs("Options:\n", stderr);
    fputs("  -h  Display this help message\n", stderr);
    fputs("  -b <backlog> the backlog\n", stderr);
    fputs("  -a <listening ip address> the ip address to listen to\n", stderr);
    fputs("  -p <listening port> the port to listen to\n", stderr);
    fputs("  -A <forwarding ip address> the ip address to forward to\n", stderr);
    fputs("  -P <forwarding port> the port to forward to\n", stderr);
    fputs("  -v verbose\n", stderr);
    fputs("  -V very verbose\n", stderr);
    exit(exit_code);
}
