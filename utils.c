#include "utils.h"

#include <stdio.h>
#include <stdlib.h>

char *ip2str(struct sockaddr *addr){
    int ip_len = INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
    char s[ip_len];
    int port;

    switch(addr->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;

            inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
            port = addr_in->sin_port;
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;

            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
            port = addr_in6->sin6_port;
            break;
        }
        default:
            break;
    }
    char *ret = malloc(ip_len + 10);
    sprintf(ret, "[%s]:%d", s, ntohs(port));
    return ret;
}


void print_path(const char *msg, struct sockaddr *local, struct sockaddr *peer) {
    char *ip_local = ip2str(local);
    char *ip_peer = ip2str(peer);
    fprintf(stderr, "Path %s -> %s: %s\n", ip_local, ip_peer, msg);
    free(ip_local);
    free(ip_peer);
}