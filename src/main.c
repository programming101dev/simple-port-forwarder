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
#include <p101_posix/p101_unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
    struct arguments   args;
    struct settings    sets;
    int                exit_code;

    err = p101_error_create(true);
    env = p101_env_create(err, true, NULL);
    p101_memset(env, &args, 0, sizeof(args));
    parse_arguments(env, argc, argv, &args);

    if(args.verbose || args.very_verbose)
    {
        p101_env_set_tracer(env, p101_env_default_tracer);
    }

    check_arguments(env, argv[0], &args);
    p101_memset(env, &sets, 0, sizeof(sets));
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

    while((opt = p101_getopt(env, argc, argv, "hvVl:a:p:A:P:s:S:n:N:b:B:")) != -1)
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
            case 'l':
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
            case 's':
            {
                args->min_seconds = optarg;
                break;
            }
            case 'S':
            {
                args->max_seconds = optarg;
                break;
            }
            case 'n':
            {
                args->min_nanoseconds = optarg;
                break;
            }
            case 'N':
            {
                args->max_nanoseconds = optarg;
                break;
            }
            case 'b':
            {
                args->min_bytes = optarg;
                break;
            }
            case 'B':
            {
                args->max_bytes = optarg;
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

    if(args->backlog == NULL)
    {
        usage(env, binary_name, EXIT_FAILURE, "The backlog is required.");
    }

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

    if((args->min_seconds == NULL && args->max_seconds != NULL) || (args->min_seconds != NULL && args->max_seconds == NULL))
    {
        usage(env, binary_name, EXIT_FAILURE, "If min-seconds is specified, max-seconds must be specified and vice versa.");
    }

    if((args->min_nanoseconds == NULL && args->max_nanoseconds != NULL) || (args->min_nanoseconds != NULL && args->max_nanoseconds == NULL))
    {
        usage(env, binary_name, EXIT_FAILURE, "If min-nanoseconds is specified, max-nanoseconds must be specified and vice versa.");
    }

    if((args->min_bytes == NULL && args->max_bytes != NULL) || (args->min_bytes != NULL && args->max_bytes == NULL))
    {
        usage(env, binary_name, EXIT_FAILURE, "If min-bytes is specified, max-bytes must be specified and vice versa.");
    }
}

static void convert_arguments(const struct p101_env *env, struct p101_error *error, const struct arguments *args, struct settings *sets)
{
    time_t min_time_t;
    time_t max_time_t;

    P101_TRACE(env);
    min_time_t         = get_time_t_min(env, error);
    max_time_t         = get_time_t_max(env, error);
    sets->verbose      = args->verbose;
    sets->very_verbose = args->very_verbose;
    sets->backlog      = parse_positive_int(env, error, args->backlog);

    if(p101_error_has_error(error))
    {
        goto done;
    }

    convert_address(env, error, args->ip_address_in, &sets->addr_in);

    if(p101_error_has_error(error))
    {
        goto done;
    }

    sets->port_in = parse_in_port_t(env, error, args->port_in);

    if(p101_error_has_error(error))
    {
        goto done;
    }

    convert_address(env, error, args->ip_address_out, &sets->addr_out);

    if(p101_error_has_error(error))
    {
        goto done;
    }

    sets->port_out = parse_in_port_t(env, error, args->port_out);

    if(p101_error_has_error(error))
    {
        goto done;
    }

    if(args->min_seconds)
    {
        sets->min_seconds = parse_time_t(env, error, min_time_t, max_time_t, args->min_seconds);

        if(p101_error_has_error(error))
        {
            goto done;
        }
    }

    if(args->max_seconds)
    {
        sets->max_seconds = parse_time_t(env, error, min_time_t, max_time_t, args->max_seconds);

        if(p101_error_has_error(error))
        {
            goto done;
        }
    }

    if(args->min_nanoseconds)
    {
        sets->min_nanoseconds = parse_long(env, error, args->min_nanoseconds);

        if(p101_error_has_error(error))
        {
            goto done;
        }
    }

    if(args->max_nanoseconds)
    {
        sets->max_nanoseconds = parse_long(env, error, args->max_nanoseconds);

        if(p101_error_has_error(error))
        {
            goto done;
        }
    }

    if(args->min_bytes)
    {
        sets->min_bytes = parse_unsigned_int(env, error, args->min_bytes);

        if(p101_error_has_error(error))
        {
            goto done;
        }
    }

    if(args->max_bytes)
    {
        sets->max_bytes = parse_unsigned_int(env, error, args->max_bytes);

        if(p101_error_has_error(error))
        {
            goto done;
        }
    }

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
            "Usage: %s [-h] [-v] [-V] -l <backlog> -a <listening ip address> -p <listening port> -A <forwarding ip address> -P <forwarding port> [-s <min seconds> -S <max seconds> -n <min nanoseconds> -N <max nanoseconds> -b <num bytes> -B <max bytes>]\n",
            program_name);
    fputs("Options:\n", stderr);
    fputs("  -h Display this help message\n", stderr);
    fputs("  -l <backlog> the backlog\n", stderr);
    fputs("  -a <listening ip address> the ip address to listen to\n", stderr);
    fputs("  -p <listening port> the port to listen to\n", stderr);
    fputs("  -A <forwarding ip address> the ip address to forward to\n", stderr);
    fputs("  -P <forwarding port> the port to forward to\n", stderr);
    fputs("  -s <min seconds> minimum number of seconds to delay between packets", stderr);
    fputs("  -S <max seconds> maximum number of seconds to delay between packets", stderr);
    fputs("  -n <min nanoseconds> minimum number of nanoseconds to delay between packets", stderr);
    fputs("  -N <max nanoseconds> maximum number of nanoseconds to delay between packets", stderr);
    fputs("  -b <num bytes> minimum number of bytes to send per packet", stderr);
    fputs("  -B <max bytes> maximum number of bytes to send per packet", stderr);
    fputs("  -v verbose\n", stderr);
    fputs("  -V very verbose\n", stderr);
    exit(exit_code);
}
