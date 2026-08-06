#include "cli.h"
#include "convert.h"
#include <p101_c/p101_ctype.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_string.h>
#include <p101_cli/p101_getopt.h>
#include <p101_cli/p101_stdlib.h>
#include <p101_cli/p101_unistd.h>
#include <p101_convert/integer.h>
#include <stdio.h>
#include <stdlib.h>

#define OPTION_MESSAGE_LEN 64    // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

void usage(const struct p101_env *env, struct p101_error *err, const char *program_name, int exit_code, const char *message)
{
    FILE *stream;

    P101_TRACE_SCOPE(env);
    stream = (exit_code == EXIT_SUCCESS) ? stdout : stderr;

    if(message)
    {
        p101_fprintf(env, err, stream, "%s\n", message);
    }

    p101_fprintf(
        env,
        err,
        stream,
        "Usage: %s [-h] [-v] [-V] -l <backlog> -a <listening ip address> -p <listening port> -A <forwarding ip address> -P <forwarding port> [-s <min seconds> -S <max seconds> -n <min nanoseconds> -N <max nanoseconds> -b <min bytes> -B <max bytes>]\n",
        program_name);
    p101_fputs(env, err, "Options:\n", stream);
    p101_fputs(env, err, "  -h Display this help message\n", stream);
    p101_fputs(env, err, "  -l <backlog> the backlog\n", stream);
    p101_fputs(env, err, "  -a <listening ip address> the ip address to listen to\n", stream);
    p101_fputs(env, err, "  -p <listening port> the port to listen to\n", stream);
    p101_fputs(env, err, "  -A <forwarding ip address> the ip address to forward to\n", stream);
    p101_fputs(env, err, "  -P <forwarding port> the port to forward to\n", stream);
    p101_fputs(env, err, "  -s <min seconds> minimum number of seconds to delay between packets\n", stream);
    p101_fputs(env, err, "  -S <max seconds> maximum number of seconds to delay between packets\n", stream);
    p101_fputs(env, err, "  -n <min nanoseconds> minimum number of nanoseconds to delay between packets\n", stream);
    p101_fputs(env, err, "  -N <max nanoseconds> minimum number of nanoseconds to delay between packets\n", stream);
    p101_fputs(env, err, "  -b <min bytes> minimum number of bytes to send per packet\n", stream);
    p101_fputs(env, err, "  -B <max bytes> maximum number of bytes to send per packet\n", stream);
    p101_fputs(env, err, "  -v verbose\n", stream);
    p101_fputs(env, err, "  -V very verbose\n", stream);
}

void parse_arguments(const struct p101_env *env, struct p101_error *err, int argc, char *argv[], struct arguments *args)
{
    int opt;

    P101_TRACE_SCOPE(env);
    opterr = 0;

    while((opt = p101_getopt(env, argc, argv, ":hvVl:a:p:A:P:s:S:n:N:b:B:")) != -1)
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
                args->show_help = true;
                break;
            }
            case ':':
            {
                char message[OPTION_MESSAGE_LEN];

                p101_snprintf(env, err, message, sizeof(message), "Option '-%c' requires an argument.", optopt ? optopt : '?');
                P101_ERROR_RAISE_USER(err, message, 1);
                break;
            }
            case '?':
            {
                char message[OPTION_MESSAGE_LEN];

                if(p101_isprint(env, optopt))
                {
                    p101_snprintf(env, err, message, sizeof(message), "Unknown option '-%c'.", optopt);
                }
                else
                {
                    p101_snprintf(env, err, message, sizeof(message), "Unknown option character 0x%02X.", (unsigned)(unsigned char)optopt);
                }
                P101_ERROR_RAISE_USER(err, message, 1);
                break;
            }
            default:
            {
                P101_ERROR_RAISE_USER(err, "Internal error: getopt returned an unsupported option.", 1);
                break;
            }
        }
    }

    if(optind < argc)
    {
        P101_ERROR_RAISE_USER(err, "Error: Too many arguments.", 1);
    }
}

void check_arguments(const struct p101_env *env, struct p101_error *err, const struct arguments *args)
{
    P101_TRACE_SCOPE(env);

    if(args->backlog == NULL)
    {
        P101_ERROR_RAISE_USER(err, "The backlog is required.", 1);
        goto done;
    }

    if(args->ip_address_in == NULL)
    {
        P101_ERROR_RAISE_USER(err, "The listening ip address is required.", 1);
        goto done;
    }

    if(args->port_in == NULL)
    {
        P101_ERROR_RAISE_USER(err, "The listening port is required.", 1);
        goto done;
    }

    if(args->ip_address_out == NULL)
    {
        P101_ERROR_RAISE_USER(err, "The forwarding ip address is required.", 1);
        goto done;
    }

    if(args->port_out == NULL)
    {
        P101_ERROR_RAISE_USER(err, "The forwarding port is required.", 1);
        goto done;
    }

    if((args->min_seconds == NULL && args->max_seconds != NULL) || (args->min_seconds != NULL && args->max_seconds == NULL))
    {
        P101_ERROR_RAISE_USER(err, "If min-seconds is specified, max-seconds must be specified and vice versa.", 1);
        goto done;
    }

    if((args->min_nanoseconds == NULL && args->max_nanoseconds != NULL) || (args->min_nanoseconds != NULL && args->max_nanoseconds == NULL))
    {
        P101_ERROR_RAISE_USER(err, "If min-nanoseconds is specified, max-nanoseconds must be specified and vice versa.", 1);
        goto done;
    }

    if((args->min_bytes == NULL && args->max_bytes != NULL) || (args->min_bytes != NULL && args->max_bytes == NULL))
    {
        P101_ERROR_RAISE_USER(err, "If min-bytes is specified, max-bytes must be specified and vice versa.", 1);
        goto done;
    }

done:
    return;
}

void convert_arguments(const struct p101_env *env, struct p101_error *err, const struct arguments *args, struct settings *sets)
{
    time_t min_time_t;
    time_t max_time_t;

    P101_TRACE_SCOPE(env);
    min_time_t         = get_time_t_min(env, err);
    max_time_t         = get_time_t_max(env, err);
    sets->verbose      = args->verbose;
    sets->very_verbose = args->very_verbose;
    sets->backlog      = p101_parse_positive_int(env, err, args->backlog, 0);

    if(p101_error_has_error(err))
    {
        goto done;
    }

    convert_address(env, err, args->ip_address_in, &sets->addr_in);

    if(p101_error_has_error(err))
    {
        goto done;
    }

    sets->port_in = parse_in_port_t(env, err, args->port_in);

    if(p101_error_has_error(err))
    {
        goto done;
    }

    convert_address(env, err, args->ip_address_out, &sets->addr_out);

    if(p101_error_has_error(err))
    {
        goto done;
    }

    sets->port_out = parse_in_port_t(env, err, args->port_out);

    if(p101_error_has_error(err))
    {
        goto done;
    }

    if(args->min_seconds)
    {
        sets->min_seconds = parse_time_t(env, err, min_time_t, max_time_t, args->min_seconds);

        if(p101_error_has_error(err))
        {
            goto done;
        }
    }

    if(args->max_seconds)
    {
        sets->max_seconds = parse_time_t(env, err, min_time_t, max_time_t, args->max_seconds);

        if(p101_error_has_error(err))
        {
            goto done;
        }
    }

    if(args->min_nanoseconds)
    {
        sets->min_nanoseconds = p101_parse_long(env, err, args->min_nanoseconds, 0);

        if(p101_error_has_error(err))
        {
            goto done;
        }
    }

    if(args->max_nanoseconds)
    {
        sets->max_nanoseconds = p101_parse_long(env, err, args->max_nanoseconds, 0);

        if(p101_error_has_error(err))
        {
            goto done;
        }
    }

    if(args->min_bytes)
    {
        sets->min_bytes = p101_parse_unsigned_int(env, err, args->min_bytes, 0);

        if(p101_error_has_error(err))
        {
            goto done;
        }
    }

    if(args->max_bytes)
    {
        sets->max_bytes = p101_parse_unsigned_int(env, err, args->max_bytes, 0);

        if(p101_error_has_error(err))
        {
            goto done;
        }
    }

done:
    return;
}
