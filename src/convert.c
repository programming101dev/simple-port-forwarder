//
// Created by D'Arcy Smith on 2024-01-12.
//

#include "convert.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <p101_c/p101_inttypes.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_string.h>
#include <p101_convert/integer.h>
#include <p101_convert/networking.h>
#include <p101_network/arpa/p101_inet.h>
#include <p101_network/net/p101_ethernet.h>
#include <p101_network/net/p101_if.h>
#include <p101_network/p101_ifaddrs.h>
#include <p101_network/p101_netdb.h>
#include <p101_network/sys/p101_socket.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

enum
{
    CONVERT_ERROR_MESSAGE_LEN = 256,
    DEFAULT_TIME_T            = 0
};

in_port_t parse_in_port_t(const struct p101_env *env, struct p101_error *error, const char *str)
{
    in_port_t p101_call_result_1;

    P101_TRACE_SCOPE(env);
    p101_call_result_1 = p101_parse_in_port_t(env, error, str);

    return p101_call_result_1;
}

time_t get_time_t_min(const struct p101_env *env, struct p101_error *error)
{
    time_t value;

    P101_TRACE_SCOPE(env);

    if(sizeof(time_t) == sizeof(char))
    {
        value = CHAR_MIN;
    }
    else if(sizeof(time_t) == sizeof(short))
    {
        value = SHRT_MIN;
    }
    else if(sizeof(time_t) == sizeof(int))
    {
        value = INT_MIN;
    }
    else if(sizeof(time_t) == sizeof(long))
    {
        value = LONG_MIN;
    }
    else if(sizeof(time_t) == sizeof(long long))
    {
        value = LLONG_MIN;
    }
    else
    {
        /*
         * An unrecognised time_t width: report it and still leave a
         * representable bound behind rather than an indeterminate value.
         */
        value = 0;
        P101_ERROR_RAISE_SYSTEM(error, "", 1);
    }

    return value;
}

time_t get_time_t_max(const struct p101_env *env, struct p101_error *error)
{
    time_t value;

    P101_TRACE_SCOPE(env);

    if(sizeof(time_t) == sizeof(char))
    {
        value = CHAR_MAX;
    }
    else if(sizeof(time_t) == sizeof(short))
    {
        value = SHRT_MAX;
    }
    else if(sizeof(time_t) == sizeof(int))
    {
        value = INT_MAX;
    }
    else if(sizeof(time_t) == sizeof(long))
    {
        value = LONG_MAX;
    }
    else if(sizeof(time_t) == sizeof(long long))
    {
        value = LLONG_MAX;
    }
    else
    {
        /*
         * An unrecognised time_t width: report it and still leave a
         * representable bound behind rather than an indeterminate value.
         */
        value = 0;
        P101_ERROR_RAISE_SYSTEM(error, "", 1);
    }

    return value;
}

time_t parse_time_t(const struct p101_env *env, struct p101_error *error, time_t min, time_t max, const char *str)
{
    long long p101_call_result_2;
    bool      p101_call_result_3;
    time_t    value;

    P101_TRACE_SCOPE(env);

    /*
     * Every failure path returns this default so a caller that ignores the
     * error object never receives an indeterminate time_t. lib_convert rejects
     * a trailing non-numeric tail as a parse failure, so the former separate
     * "invalid characters" check is part of the parse error below.
     */
    value              = DEFAULT_TIME_T;
    p101_call_result_2 = p101_parse_long_long(env, error, str, (long long)DEFAULT_TIME_T);
    p101_call_result_3 = p101_error_has_error(error);

    if(p101_call_result_3)
    {
        P101_ERROR_RAISE_USER(error, "Error parsing time_t.", 1);
        goto done;
    }

    if(p101_call_result_2 < (long long)min || p101_call_result_2 > (long long)max)
    {
        P101_ERROR_RAISE_USER(error, "time_t value out of range.", 3);
        goto done;
    }

    value = (time_t)p101_call_result_2;

done:
    return value;
}

void convert_address(const struct p101_env *env, struct p101_error *error, const char *address, struct sockaddr_storage *addr)
{
    socklen_t p101_call_result_1;
    bool      p101_call_result_2;

    P101_TRACE_SCOPE(env);
    p101_call_result_1 = p101_convert_address(env, error, address, addr);
    p101_call_result_2 = p101_error_has_error(error);

    /*
     * The forwarder's -a contract is IPv4/IPv6 only. p101_convert_address
     * also accepts explicit Unix pathnames, so reject that family here and
     * keep this program's historical diagnostic for unparseable input.
     */
    if((p101_call_result_2 && p101_call_result_1 == 0U) || (!p101_call_result_2 && addr->ss_family == AF_UNIX))
    {
        char message[CONVERT_ERROR_MESSAGE_LEN];

        p101_error_reset(error);
        p101_snprintf(env, error, message, sizeof(message), "%s is not an IPv4 or an IPv6 address", address);
        P101_ERROR_RAISE_USER(error, message, 1);
    }
}

void sockaddr_to_string(const struct p101_env *env, struct p101_error *err, const struct sockaddr_storage *addr, char *ipstr, socklen_t max_size)
{
    P101_TRACE_SCOPE(env);

    if(addr->ss_family == AF_INET)
    {
        const struct sockaddr_in *addr_in;

        addr_in = (const struct sockaddr_in *)addr;
        p101_inet_ntop(env, err, AF_INET, &addr_in->sin_addr, ipstr, max_size);
    }
    else if(addr->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *addr_in6;

        addr_in6 = (const struct sockaddr_in6 *)addr;
        p101_inet_ntop(env, err, AF_INET6, &addr_in6->sin6_addr, ipstr, max_size);
    }
    else
    {
        P101_ERROR_RAISE_USER(err, "sockaddr family must be AF_INET or AF_INET6", 1);
    }
}
