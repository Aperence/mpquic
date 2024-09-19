#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

char *ip2str(struct sockaddr *addr);
void print_path(const char *msg, struct sockaddr *local, struct sockaddr *peer);

#endif