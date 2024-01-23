#ifndef SERVER_CONVERT_H
#define SERVER_CONVERT_H

#include <netinet/in.h>
#include <p101_env/env.h>
#include <sys/socket.h>
#include <time.h>

in_port_t    parse_in_port_t(const struct p101_env *env, struct p101_error *error, const char *str);
time_t       get_time_t_min(const struct p101_env *env, struct p101_error *error) __attribute__((const));
time_t       get_time_t_max(const struct p101_env *env, struct p101_error *error) __attribute__((const));
time_t       parse_time_t(const struct p101_env *env, struct p101_error *error, time_t min, time_t max, const char *str);
long         parse_long(const struct p101_env *env, struct p101_error *error, const char *str);
int          parse_positive_int(const struct p101_env *env, struct p101_error *error, const char *str);
unsigned int parse_unsigned_int(const struct p101_env *env, struct p101_error *error, const char *str);
void         convert_address(const struct p101_env *env, struct p101_error *error, const char *address, struct sockaddr_storage *addr);
void         sockaddr_to_string(const struct p101_env *env, struct p101_error *err, const struct sockaddr_storage *addr, char *ipstr, socklen_t max_size);

#endif    // SERVER_CONVERT_H
