// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "quiche-client.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <ev.h>

#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define NUMBER_SOCKETS 2

typedef struct response_part{
    uint8_t *data;
    ssize_t len;
    struct response_part *next;
} response_part_t;

typedef struct response{
    response_part_t *head;
    response_part_t *tail;
    ssize_t total_len;
}response_t;

typedef struct ip_addr_itf{
    struct sockaddr_storage wifi;
    socklen_t wifi_len;
    struct sockaddr_storage cellular;
    socklen_t cellular_len;
}ip_addr_itf_t;

typedef struct socket_state{
    int idx;
    
    struct conn_io *conn;
}socket_state_t;

struct conn_io {
    ev_timer timer;

    int *sockets;
    struct sockaddr_storage *local_addr;
    socklen_t *local_addr_len;

    struct sockaddr *peer;
    socklen_t peer_len;

    const char *host;
    const char *path;

    quiche_conn *conn;

    quiche_h3_conn *http3;

    bool req_sent;
    bool settings_received;

    response_t response;
    
    int failed_malloc;
};

int add_response_part(struct conn_io *conn, uint8_t *data, ssize_t len){
    response_part_t *new_response = malloc(sizeof(response_part_t));
    if (!new_response) return -1;
    new_response->data = malloc(len);
    if (!new_response->data) return -1;
    memcpy(new_response->data, data, len);
    new_response->len = len;
    new_response->next = NULL;
    conn->response.total_len += len;

    if (conn->response.head == NULL){
        conn->response.head = new_response;
        conn->response.tail = new_response;
    }else{
        conn->response.tail->next = new_response;
        conn->response.tail = new_response;
    }
    return 0;
}

uint8_t *construct_full_response(response_t response){
    uint8_t *ret = malloc(response.total_len+1);
    if (!ret) return NULL;
    int offset = 0;
    response_part_t *res = response.head;
    while (res){
        memcpy(ret + offset, res->data, res->len);
        offset += res->len;
        res = res->next;
    }
    ret[offset] = '\0';
    return ret;
}

void free_responses(response_t response){
    response_part_t *res = response.head;
    response_part_t *temp;
    while (res){
        temp = res;
        res = res->next;
        free(temp->data);
        free(temp);
    }
}

http_response_t *new_response(int status, uint8_t *res, ssize_t len){
    http_response_t *response = malloc(sizeof(http_response_t));
    response->status = status;
    response->data = res;
    response->len = len;
    return response;
}

static void print_ip_addr(struct sockaddr *addr){
    char s[INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN];

    switch(addr->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;

            ////char s[INET_ADDRSTRLEN] = '\0';
                // this is large enough to include terminating null

            inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;
            
            ////char s[INET6_ADDRSTRLEN] = '\0';
                // not sure if large enough to include terminating null?

            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
            break;
        }
        default:
            break;
    }
    printf("IP address: %s\n", s);
}

ip_addr_itf_t *get_addrs(int family){
    ip_addr_itf_t *ret = malloc(sizeof(ip_addr_itf_t));
    memset(ret, 0, sizeof(ip_addr_itf_t));

    struct ifaddrs *ifaddr;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL;
             ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != family)
            continue;
        
        if (family == AF_INET6){
            struct sockaddr_in6 *temp = (struct sockaddr_in6 *) ifa->ifa_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&temp->sin6_addr)){
                // Link local address, skip
                continue;
            }
        }

        struct sockaddr_storage *addr;
        socklen_t *len;
        if (strncmp(ifa->ifa_name, "en", 2) == 0 && ret->wifi_len == 0){
            addr = &ret->wifi;
            len = &ret->wifi_len;
        }else if (strncmp(ifa->ifa_name, "pdp_ip", 6) == 0 && ret->cellular_len == 0){
            addr = &ret->cellular;
            len = &ret->cellular_len;
        }else{
            continue;
        }
        
        *len = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        memcpy(addr, ifa->ifa_addr, *len);
    }

    freeifaddrs(ifaddr);
    
    return ret;
}

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

static void handle_path_events(struct conn_io *conn){
    quiche_path_event *e;

    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    while ((e = quiche_conn_path_event_next(conn->conn))){
        enum quiche_path_event_type type = quiche_path_event_type(e);
        switch (type)
        {
            case QUICHE_PATH_EVENT_VALIDATED:
                fprintf(stderr, "path validated");
                break;
            case QUICHE_PATH_EVENT_FAILED_VALIDATION:
                fprintf(stderr, "path failed validation");
                break;
            case QUICHE_PATH_EVENT_CLOSED:
                fprintf(stderr, "path closed");
                break;
            case QUICHE_PATH_EVENT_REUSED_SOURCE_CONNECTION_ID:
                fprintf(stderr, "reused connection id");
                break;
            default:
                break;
        }
    }
}

static void probe_paths(struct conn_io *conn){
    uint64_t seq = 0;
    for (size_t i = 0; i < NUMBER_SOCKETS; i++)
    {
        struct sockaddr *local = (struct sockaddr *)&conn->local_addr[i];
        socklen_t local_len = conn->local_addr_len[i];
        struct sockaddr *peer = conn->peer;
        socklen_t peer_len = conn->peer_len;
        if (quiche_conn_is_path_validated(conn->conn, local, local_len, peer, peer_len) == QUICHE_ERR_INVALID_STATE 
            && quiche_conn_available_dcids(conn->conn) > 1)
        {
            quiche_conn_probe_path(conn->conn, local, local_len, peer, peer_len, &seq);
        }
    }
    
}

static void schedule(struct conn_io *conn){
}

static int provide_cids(struct conn_io *conn){
    if (quiche_conn_scids_left(conn->conn) < NUMBER_SOCKETS)
        return -1;

    ssize_t rand_len;
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0)
        return -2;

    for (size_t i = 0; i < NUMBER_SOCKETS; i++)
    {
        uint64_t seq;
        uint8_t scid[LOCAL_CONN_ID_LEN];
        rand_len = read(rng, &scid, sizeof(scid));
        if (rand_len < 0)
            return -3;
        
        uint8_t reset[16];
        rand_len = read(rng, &reset, sizeof(reset));
        if (rand_len < 0)
            return -4;
        
        quiche_conn_new_scid(conn->conn, scid, LOCAL_CONN_ID_LEN, reset, false, &seq);
    }
    
    close(rng);
    return 0;
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];

    quiche_send_info send_info;

    for (size_t i = 0; i < NUMBER_SOCKETS; i++)
    {
        int sock = conn_io->sockets[i];

        struct sockaddr_storage *from = &conn_io->local_addr[i];
        socklen_t len = conn_io->local_addr_len[i];

        quiche_socket_addr_iter *iter = quiche_conn_paths_iter(conn_io->conn, (struct sockaddr *) from, len);

        struct sockaddr_storage peer;
        socklen_t len_peer = sizeof(peer);

        while(quiche_socket_addr_iter_next(iter, &peer, (size_t *) &len_peer)){
            while (1) {
                ssize_t written = quiche_conn_send_on_path(conn_io->conn, 
                                                           out, sizeof(out), (struct sockaddr *) from, len, 
                                                           (struct sockaddr *) &peer, len_peer, &send_info);

                if (written == QUICHE_ERR_DONE) {
                    fprintf(stderr, "done writing\n");
                    break;
                }

                if (written < 0) {
                    fprintf(stderr, "failed to create packet: %zd\n", written);
                    return;
                }

                ssize_t sent = sendto(sock, out, written, 0,
                                    (struct sockaddr *) &send_info.to,
                                    send_info.to_len);

                if (sent != written) {
                    perror("failed to send");
                    return;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
            }

            double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
            conn_io->timer.repeat = t;
            ev_timer_again(loop, &conn_io->timer);
        }
    }
}

static int for_each_setting(uint64_t identifier, uint64_t value,
                           void *argp) {
    fprintf(stderr, "got HTTP/3 SETTING: %" PRIu64 "=%" PRIu64 "\n",
            identifier, value);

    return 0;
}

static int for_each_header(uint8_t *name, size_t name_len,
                           uint8_t *value, size_t value_len,
                           void *argp) {
    fprintf(stderr, "got HTTP header: %.*s=%.*s\n",
            (int) name_len, name, (int) value_len, value);

    return 0;
}

static void recv_cb(EV_P_ ev_io *w, int revents) {

    socket_state_t *sock_state = w->data;
    struct conn_io *conn_io = sock_state->conn;

    static uint8_t buf[65535];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conn_io->sockets[sock_state->idx], buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *) &peer_addr,
            peer_addr_len,

            (struct sockaddr *) &conn_io->local_addr[sock_state->idx],
            conn_io->local_addr_len[sock_state->idx],
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0) {
            fprintf(stderr, "failed to process packet: %zd\n", done);
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);
    }

    fprintf(stderr, "done reading\n");

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn)){
        probe_paths(conn_io);
        handle_path_events(conn_io);
        schedule(conn_io);
    }

    if (quiche_conn_is_established(conn_io->conn) && !conn_io->req_sent) {
        const uint8_t *app_proto;
        size_t app_proto_len;

        provide_cids(conn_io);

        quiche_conn_application_proto(conn_io->conn, &app_proto, &app_proto_len);

        fprintf(stderr, "connection established: %.*s\n",
                (int) app_proto_len, app_proto);

        quiche_h3_config *config = quiche_h3_config_new();
        if (config == NULL) {
            fprintf(stderr, "failed to create HTTP/3 config\n");
            return;
        }

        conn_io->http3 = quiche_h3_conn_new_with_transport(conn_io->conn, config);
        if (conn_io->http3 == NULL) {
            fprintf(stderr, "failed to create HTTP/3 connection\n");
            return;
        }

        quiche_h3_config_free(config);

        quiche_h3_header headers[] = {
            {
                .name = (const uint8_t *) ":method",
                .name_len = sizeof(":method") - 1,

                .value = (const uint8_t *) "GET",
                .value_len = sizeof("GET") - 1,
            },

            {
                .name = (const uint8_t *) ":scheme",
                .name_len = sizeof(":scheme") - 1,

                .value = (const uint8_t *) "https",
                .value_len = sizeof("https") - 1,
            },

            {
                .name = (const uint8_t *) ":authority",
                .name_len = sizeof(":authority") - 1,

                .value = (const uint8_t *) conn_io->host,
                .value_len = strlen(conn_io->host),
            },

            {
                .name = (const uint8_t *) ":path",
                .name_len = sizeof(":path") - 1,

                .value = (const uint8_t *) conn_io->path,
                .value_len = strlen(conn_io->path),
            },

            {
                .name = (const uint8_t *) "user-agent",
                .name_len = sizeof("user-agent") - 1,

                .value = (const uint8_t *) "quiche",
                .value_len = sizeof("quiche") - 1,
            },
        };

        int64_t stream_id = quiche_h3_send_request(conn_io->http3,
                                                   conn_io->conn,
                                                   headers, 5, true);

        fprintf(stderr, "sent HTTP request %" PRId64 "\n", stream_id);

        conn_io->req_sent = true;
    }

    if (quiche_conn_is_established(conn_io->conn)) {
        quiche_h3_event *ev;

        while (1) {
            int64_t s = quiche_h3_conn_poll(conn_io->http3,
                                            conn_io->conn,
                                            &ev);

            if (s < 0) {
                break;
            }

            if (!conn_io->settings_received) {
                int rc = quiche_h3_for_each_setting(conn_io->http3,
                                                    for_each_setting,
                                                    NULL);

                if (rc == 0) {
                    conn_io->settings_received = true;
                }
            }

            switch (quiche_h3_event_type(ev)) {
                case QUICHE_H3_EVENT_HEADERS: {
                    int rc = quiche_h3_event_for_each_header(ev, for_each_header,
                                                             NULL);

                    if (rc != 0) {
                        fprintf(stderr, "failed to process headers");
                    }

                    break;
                }

                case QUICHE_H3_EVENT_DATA: {
                    for (;;) {
                        ssize_t len = quiche_h3_recv_body(conn_io->http3,
                                                          conn_io->conn, s,
                                                          buf, sizeof(buf));

                        if (len <= 0) {
                            break;
                        }

                        if (add_response_part(conn_io, buf, len) == -1){
                            conn_io->failed_malloc = 1;
                            ev_break(EV_A_ EVBREAK_ONE);
                        }
                    }

                    break;
                }

                case QUICHE_H3_EVENT_FINISHED:
                    if (quiche_conn_close(conn_io->conn, true, 0, (uint8_t *) "", 0) < 0) {
                        fprintf(stderr, "failed to close connection\n");
                    }
                    break;

                case QUICHE_H3_EVENT_RESET:
                    fprintf(stderr, "request was reset\n");

                    if (quiche_conn_close(conn_io->conn, true, 0, (uint8_t *) "", 0) < 0) {
                        fprintf(stderr, "failed to close connection\n");
                    }
                    break;

                case QUICHE_H3_EVENT_PRIORITY_UPDATE:
                    break;

                case QUICHE_H3_EVENT_GOAWAY: {
                    fprintf(stderr, "got GOAWAY\n");
                    break;
                }
            }

            quiche_h3_event_free(ev);
        }
    }

    flush_egress(loop, conn_io);
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

        fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns\n",
                stats.recv, stats.sent, stats.lost, path_stats.rtt);

        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

int get_sockets(int family, int number_sockets, struct conn_io *conn_io){

    // ip_addr_itf_t *ips = get_addrs(peer->ai_family);
    /*
    if (ips->wifi_len != 0){
        printf("Using Wifi itf\n");
        bind(sock, (struct sockaddr *) &ips->wifi, ips->wifi_len);
    }else{
        printf("Using cellular itf\n");
        bind(sock, (struct sockaddr *) &ips->cellular, ips->cellular_len);
    }*/
    
    /*
    const char* device_name = "en0"; // wifi
    //const char* device_name = "pdp_ip0"; // cellular
    int interfaceIndex = if_nametoindex(device_name);
    
    
    if (setsockopt(sock, peer->ai_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP,
                   peer->ai_family == AF_INET6 ? IPV6_BOUND_IF : IP_BOUND_IF,
                   &interfaceIndex, sizeof(interfaceIndex)) != 0){
        char *msg = "failed to bind socket to wifi";
        return new_response(-1, (uint8_t *) msg, strlen(msg));
    }
    */

    conn_io->sockets = malloc(sizeof(int) * number_sockets);
    conn_io->local_addr = malloc(sizeof(struct sockaddr_storage) * number_sockets);
    conn_io->local_addr_len = malloc(sizeof(socklen_t) * number_sockets);
    for (size_t i = 0; i < number_sockets; i++)
    {
        int sock = socket(family, SOCK_DGRAM, 0);
        if (sock < 0) {
            return -1;
        }

        if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
            return -2;
        }

        conn_io->sockets[i] = sock;

        conn_io->local_addr_len[i] = sizeof(struct sockaddr_storage);

        if (getsockname(sock, (struct sockaddr *) &conn_io->local_addr[i],
                        &conn_io->local_addr_len[i]) != 0)
        {
            return -3;
        }
    }
    
    return 0;
}

http_response_t *quiche_fetch(const char *host, const char *port, const char *path){

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *peer;
    if (getaddrinfo(host, port, &hints, &peer) != 0) {
        char *msg = "failed to resolve host";
        return new_response(-1, (uint8_t *) msg, strlen(msg));
    }

    quiche_config *config = quiche_config_new(0xbabababa);
    if (config == NULL) {
        char *msg = "failed to create config";
        return new_response(-1, (uint8_t *) msg, strlen(msg));
    }

    quiche_config_set_application_protos(config,
        (uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL,
        sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1);

    quiche_config_set_max_idle_timeout(config, 5000);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_set_disable_active_migration(config, true);

    if (getenv("SSLKEYLOGFILE")) {
      quiche_config_log_keys(config);
    }

    // ABC: old config creation here

    uint8_t scid[LOCAL_CONN_ID_LEN];
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        char *msg = "failed to open /dev/urandom";
        return new_response(-1, (uint8_t *) msg, strlen(msg));
    }

    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        char *msg = "failed to create connection ID";
        return new_response(-1, (uint8_t *) msg, strlen(msg));
    }

    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        char *msg = "failed to allocate connection IO";
        return new_response(-1, (uint8_t *) msg, strlen(msg));
    }

    get_sockets(peer->ai_family, NUMBER_SOCKETS, conn_io);
    
    print_ip_addr((struct sockaddr *) &conn_io->local_addr[0]);

    quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid, sizeof(scid),
                                       (struct sockaddr *) &conn_io->local_addr[0],
                                       conn_io->local_addr_len[0],
                                       peer->ai_addr, peer->ai_addrlen, config);

    if (getenv("SSLKEYLOGFILE")) {
        quiche_conn_set_keylog_path(conn, getenv("SSLKEYLOGFILE"));
    }

    if (conn == NULL) {
        char *msg = "failed to create connection";
        return new_response(-1, (uint8_t *) msg, strlen(msg));
    }

    conn_io->conn = conn;
    conn_io->http3 = NULL;
    conn_io->host = host;
    conn_io->path = path;
    conn_io->req_sent = false;
    conn_io->settings_received = false;
    conn_io->failed_malloc = 0;
    conn_io->peer = peer->ai_addr;
    conn_io->peer_len = peer->ai_addrlen;
    conn_io->response.head = NULL;
    conn_io->response.tail = NULL;
    conn_io->response.total_len = 0;

    ev_io watchers[NUMBER_SOCKETS];

    struct ev_loop *loop = ev_default_loop(0);

    socket_state_t *sock_states = malloc(sizeof(socket_state_t) * NUMBER_SOCKETS);
    for (size_t i = 0; i < NUMBER_SOCKETS; i++)
    {
        socket_state_t *sock_state = &sock_states[i];
        sock_state->conn = conn_io;
        sock_state->idx = i;

        ev_io_init(&watchers[i], recv_cb, conn_io->sockets[i], EV_READ);
        ev_io_start(loop, &watchers[i]);
        watchers[i].data = sock_state;
    }
    

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    flush_egress(loop, conn_io);

    ev_loop(loop, 0);

    freeaddrinfo(peer);

    if (conn_io->http3)
        quiche_h3_conn_free(conn_io->http3);

    quiche_conn_free(conn);

    quiche_config_free(config);
    
    if (!conn_io->req_sent){
        char *msg = "failed to send request";
        return new_response(-2, (uint8_t *) msg, strlen(msg));
    }
    
    if (conn_io->failed_malloc){
        char *msg = "failed to allocate memory for response";
        free_responses(conn_io->response);
        return new_response(-3, (uint8_t *) msg, strlen(msg));
    }

    uint8_t *out_res = construct_full_response(conn_io->response);

    free_responses(conn_io->response);
    
    if (!out_res){
        char *msg = "failed to create full response";
        return new_response(-4, (uint8_t *) msg, strlen(msg));
    }

    return new_response(0, out_res, conn_io->response.total_len);
}


int main(int argc, char const *argv[])
{
    http_response_t *res = quiche_fetch(argv[1], argv[2], "/");

    int fd = open("out.html", O_WRONLY | O_CREAT, 0666);
    write(fd, res->data, res->len);
    close(fd);

    return 0;
}
