//
// Created by D'Arcy Smith on 2024-01-12.
//

#ifndef SERVER_CONVERT_H
#define SERVER_CONVERT_H

#include <netinet/in.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <sys/socket.h>

in_port_t parse_in_port_t(const struct p101_env *env, struct p101_error *error, const char *str);
int       parse_positive_int(const struct p101_env *env, struct p101_error *error, const char *str);
void      convert_address(const struct p101_env *env, struct p101_error *error, const char *address, struct sockaddr_storage *addr);

#endif    // SERVER_CONVERT_H
