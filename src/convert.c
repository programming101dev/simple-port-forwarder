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
#include <p101_network/arpa/p101_inet.h>
#include <p101_network/net/p101_ethernet.h>
#include <p101_network/net/p101_if.h>
#include <p101_network/p101_ifaddrs.h>
#include <p101_network/p101_netdb.h>
#include <p101_network/sys/p101_socket.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#define BASE_TEN 10    // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

enum
{
    CONVERT_ERROR_MESSAGE_LEN = 256
};

in_port_t parse_in_port_t(const struct p101_env *env, struct p101_error *error, const char *str)
{
    uint16_t parsed_value;

    P101_TRACE_SCOPE(env);
    parsed_value = p101_parse_uint16_t(env, error, str, 0);

    return parsed_value;
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
        P101_ERROR_RAISE_SYSTEM(error, "", 1);
    }

    return value;
}

time_t parse_time_t(const struct p101_env *env, struct p101_error *error, time_t min, time_t max, const char *str)
{
    char    *endptr;
    intmax_t parsed_value;

    P101_TRACE_SCOPE(env);
    parsed_value = p101_strtoimax(env, error, str, &endptr, BASE_TEN);

    if(p101_error_has_error(error))
    {
        P101_ERROR_RAISE_USER(error, "Error parsing time_t.", 1);
        goto done;
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        P101_ERROR_RAISE_USER(error, "Invalid characters in time_t input.", 2);
        goto done;
    }

    if(parsed_value < min || parsed_value > max)
    {
        P101_ERROR_RAISE_USER(error, "time_t value out of range.", 3);
        goto done;
    }

done:
    return parsed_value;
}

void convert_address(const struct p101_env *env, struct p101_error *error, const char *address, struct sockaddr_storage *addr)
{
    int ipv4_result;
    int ipv6_result;

    P101_TRACE_SCOPE(env);
    p101_memset(env, addr, 0, sizeof(*addr));

    ipv4_result = p101_inet_pton(env, error, AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr));
    if(ipv4_result == 1)
    {
        addr->ss_family = AF_INET;
    }
    else
    {
        if(ipv4_result == 0 && p101_error_is_errno(error, EINVAL))
        {
            p101_error_reset(error);
        }
        if(p101_error_has_error(error))
        {
            goto done;
        }

        ipv6_result = p101_inet_pton(env, error, AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr));
        if(ipv6_result == 1)
        {
            addr->ss_family = AF_INET6;
        }
        else if(ipv6_result == 0 && p101_error_is_errno(error, EINVAL))
        {
            char message[CONVERT_ERROR_MESSAGE_LEN];

            p101_error_reset(error);
            p101_snprintf(env, error, message, sizeof(message), "%s is not an IPv4 or an IPv6 address", address);
            P101_ERROR_RAISE_USER(error, message, 1);
        }
    }

done:
    return;
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
