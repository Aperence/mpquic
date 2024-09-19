// Copyright (C) 2018-2019, Cloudflare, Inc.
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
#include "utils.h"

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

#include <ev.h>
#include <uthash.h>

#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

struct connections {
    int sock;

    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;

    struct conn_io *h;
};

struct connection_ids_state {
    uint8_t cid[LOCAL_CONN_ID_LEN];
    int id;
    UT_hash_handle hh;
};

struct connection_ids{
    struct connection_ids_state *h;
};

typedef struct schedule_state{
    int idx;
    int number_paths;
}schedule_state_t;

struct conn_io {
    ev_timer timer;

    int sock;
    int id;

    quiche_conn *conn;
    quiche_h3_conn *http3;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    UT_hash_handle hh;

    int file;
    int stream;
    schedule_state_t schedule_data;
};

static int id = 0;

static quiche_config *config = NULL;

static quiche_h3_config *http3_config = NULL;

static struct connections *conns = NULL;
static struct connection_ids *conns_id = NULL;

static void timeout_cb(EV_P_ ev_timer *w, int revents);

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

static void handle_path_events(struct conn_io *conn){
    uint64_t seq;
    quiche_path_event *e;

    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    while ((e = quiche_conn_path_event_next(conn->conn))){
        enum quiche_path_event_type type = quiche_path_event_type(e);
        switch (type)
        {
            case QUICHE_PATH_EVENT_NEW:
                quiche_path_event_new(e, &local, &local_len, &peer, &peer_len);
                print_path("new path", (struct sockaddr *) &local, (struct sockaddr *) &peer);
                quiche_conn_probe_path(conn->conn, (struct sockaddr *) &local, 
                                       local_len, (struct sockaddr *) &peer, 
                                       peer_len, &seq);
                break;
            case QUICHE_PATH_EVENT_VALIDATED:
                quiche_path_event_validated(e, &local, &local_len, &peer, &peer_len);
                print_path("path validated", (struct sockaddr *) &local, (struct sockaddr *) &peer);
                conn->schedule_data.number_paths++;
                break;
            case QUICHE_PATH_EVENT_FAILED_VALIDATION:
                quiche_path_event_failed_validation(e, &local, &local_len, &peer, &peer_len);
                print_path("path failed validation", (struct sockaddr *) &local, (struct sockaddr *) &peer);
                break;
            case QUICHE_PATH_EVENT_CLOSED:
                quiche_path_event_closed(e, &local, &local_len, &peer, &peer_len);
                print_path("path closed", (struct sockaddr *) &local, (struct sockaddr *) &peer);
                break;
            case QUICHE_PATH_EVENT_REUSED_SOURCE_CONNECTION_ID:
                fprintf(stderr, "reused connection id");
                break;
            default:
                break;
        }
    }
}

static int provide_cids(struct conn_io *conn){
    ssize_t rand_len;
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0)
        return -2;

    while (quiche_conn_scids_left(conn->conn) > 0)
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

        struct connection_ids_state *st = malloc(sizeof(struct connection_ids_state));
        memcpy(st->cid, scid, LOCAL_CONN_ID_LEN);
        st->id = conn->id;
        HASH_ADD(hh, conns_id->h, cid, LOCAL_CONN_ID_LEN, st);
    }
    
    close(rng);
    return 0;
}

static void schedule(struct conn_io *conn){
    uint64_t seq;
    int offset = conn->schedule_data.idx;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    quiche_socket_addr_iter *iter = quiche_conn_paths_iter(conn->conn, (struct sockaddr *) &conns->local_addr, conns->local_addr_len);
    for (size_t i = 0; i < offset + 1; i++){
        quiche_socket_addr_iter_next(iter, &peer, (size_t *) &peer_len);
    }
    quiche_socket_addr_iter_free(iter);
    conn->schedule_data.idx = (offset+ 1) % conn->schedule_data.number_paths;
    quiche_conn_migrate(conn->conn, 
                        (struct sockaddr *) &conns->local_addr, conns->local_addr_len,
                        (struct sockaddr *) &peer, peer_len, &seq);
    print_path("migrating", (struct sockaddr *) &conns->local_addr, (struct sockaddr *) &peer);
}

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];

    quiche_send_info send_info;

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);

        if (written == QUICHE_ERR_DONE) {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        print_path("sending data", (struct sockaddr *) &send_info.from, (struct sockaddr *) &send_info.to);

        ssize_t sent = sendto(conn_io->sock, out, written, 0,
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

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
    if ((token_len < sizeof("quiche") - 1) ||
         memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static uint8_t *gen_cid(uint8_t *cid, size_t cid_len) {
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, cid, cid_len);
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    return cid;
}

static struct conn_io *create_conn(uint8_t *scid, size_t scid_len,
                                   uint8_t *odcid, size_t odcid_len,
                                   struct sockaddr *local_addr,
                                   socklen_t local_addr_len,
                                   struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len)
{
    struct conn_io *conn_io = calloc(1, sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return NULL;
    }

    if (scid_len != LOCAL_CONN_ID_LEN) {
        fprintf(stderr, "failed, scid length too short\n");
    }

    quiche_conn *conn = quiche_accept(scid, LOCAL_CONN_ID_LEN,
                                      odcid, odcid_len,
                                      local_addr,
                                      local_addr_len,
                                      (struct sockaddr *) peer_addr,
                                      peer_addr_len,
                                      config);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return NULL;
    }

    conn_io->sock = conns->sock;
    conn_io->conn = conn;

    memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
    conn_io->peer_addr_len = peer_addr_len;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    conn_io->file = -1;
    conn_io->schedule_data.idx = 0;
    conn_io->schedule_data.number_paths = 1;
    conn_io->id = id;
    
    struct connection_ids_state *st = malloc(sizeof(struct connection_ids_state));
    memcpy(st->cid, scid, LOCAL_CONN_ID_LEN);
    st->id = id;

    id++;

    HASH_ADD(hh, conns_id->h, cid, LOCAL_CONN_ID_LEN, st);
    HASH_ADD(hh, conns->h, id, sizeof(int), conn_io);

    fprintf(stderr, "new connection\n");

    return conn_io;
}

static int for_each_header(uint8_t *name, size_t name_len,
                           uint8_t *value, size_t value_len,
                           void *argp) {
    fprintf(stderr, "got HTTP header: %.*s=%.*s\n",
            (int) name_len, name, (int) value_len, value);

    if (strncmp(name, ":path", name_len) == 0){
        char *path = argp;
        char temp[value_len+1];
        memcpy(temp, value, value_len);
        temp[value_len] = '\0';
        // transform the path in our local path (data/*)
        int written = sprintf(path, "data%s", temp);
        path[written] = 0;
    }
    return 0;
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *tmp, *conn_io = NULL;
    struct connection_ids_state *st_tmp, *st = NULL;

    static uint8_t buf[65535];
    static uint8_t file_buf[65535];
    static uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t readed = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (readed < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, readed, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            fprintf(stderr, "failed to parse header: %d\n", rc);
            return;
        }

        HASH_FIND(hh, conns_id->h, dcid, dcid_len, st);
        if (st){
            HASH_FIND(hh, conns->h, &st->id, sizeof(int), conn_io);
        }
            
        if (conn_io == NULL) {
            if (!quiche_version_is_supported(version)) {
                fprintf(stderr, "version negotiation\n");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0) {
                    fprintf(stderr, "failed to create vneg packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }

            if (token_len == 0) {
                fprintf(stderr, "stateless retry\n");

                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len,
                           token, &token_len);

                uint8_t new_cid[LOCAL_CONN_ID_LEN];

                if (gen_cid(new_cid, LOCAL_CONN_ID_LEN) == NULL) {
                    continue;
                }

                ssize_t written = quiche_retry(scid, scid_len,
                                               dcid, dcid_len,
                                               new_cid, LOCAL_CONN_ID_LEN,
                                               token, token_len,
                                               version, out, sizeof(out));

                if (written < 0) {
                    fprintf(stderr, "failed to create retry packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }


            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                               odcid, &odcid_len)) {
                fprintf(stderr, "invalid address validation token\n");
                continue;
            }

            conn_io = create_conn(dcid, dcid_len, odcid, odcid_len,
                                  (struct sockaddr *) &conns->local_addr, conns->local_addr_len,
                                  &peer_addr, peer_addr_len);

            if (conn_io == NULL) {
                continue;
            }
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *)&peer_addr,
            peer_addr_len,

            (struct sockaddr *) &conns->local_addr,
            conns->local_addr_len,
        };

        print_path("received", (struct sockaddr *) &conns->local_addr, (struct sockaddr *) &peer_addr);

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, readed, &recv_info);

        if (done < 0) {
            fprintf(stderr, "failed to process packet: %zd\n", done);
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);

        if (quiche_conn_is_established(conn_io->conn)) {

            provide_cids(conn_io);
            handle_path_events(conn_io);

            quiche_h3_event *ev;

            if (conn_io->http3 == NULL) {
                conn_io->http3 = quiche_h3_conn_new_with_transport(conn_io->conn,
                                                                   http3_config);
                if (conn_io->http3 == NULL) {
                    fprintf(stderr, "failed to create HTTP/3 connection\n");
                    continue;
                }
            }

            while (1) {
                char path[1024];
                int64_t s = quiche_h3_conn_poll(conn_io->http3,
                                                conn_io->conn,
                                                &ev);

                if (s < 0) {
                    break;
                }

                switch (quiche_h3_event_type(ev)) {
                    case QUICHE_H3_EVENT_HEADERS: {
                        int rc = quiche_h3_event_for_each_header(ev,
                                                                 for_each_header,
                                                                 path);
                        if (rc != 0) {
                            fprintf(stderr, "failed to process headers\n");
                        }

                        printf("%s\n", path);

                        int file = open(path, O_RDONLY);
                        if (file < 0){
                            quiche_h3_header headers[] = {
                                {
                                    .name = (const uint8_t *) ":status",
                                    .name_len = sizeof(":status") - 1,

                                    .value = (const uint8_t *) "404",
                                    .value_len = sizeof("404") - 1,
                                },

                                {
                                    .name = (const uint8_t *) "server",
                                    .name_len = sizeof("server") - 1,

                                    .value = (const uint8_t *) "quiche",
                                    .value_len = sizeof("quiche") - 1,
                                },
                            };

                            quiche_h3_send_response(conn_io->http3, conn_io->conn,
                                                    s, headers, 3, true);
                        }else{
                            uint8_t content_length[256];

                            struct stat st;
                            fstat(file, &st);
                            int size = sprintf(content_length, "%d", st.st_size);

                            quiche_h3_header headers[] = {
                                {
                                    .name = (const uint8_t *) ":status",
                                    .name_len = sizeof(":status") - 1,

                                    .value = (const uint8_t *) "200",
                                    .value_len = sizeof("200") - 1,
                                },

                                {
                                    .name = (const uint8_t *) "server",
                                    .name_len = sizeof("server") - 1,

                                    .value = (const uint8_t *) "quiche",
                                    .value_len = sizeof("quiche") - 1,
                                },

                                {
                                    .name = (const uint8_t *) "content-length",
                                    .name_len = sizeof("content-length") - 1,

                                    .value = (const uint8_t *) content_length,
                                    .value_len = size,
                                },
                            };

                            quiche_h3_send_response(conn_io->http3, conn_io->conn,
                                                    s, headers, 3, false);

                            conn_io->file = file;
                            conn_io->stream = s;
                        }
                        break;
                    }

                    case QUICHE_H3_EVENT_DATA: {
                        fprintf(stderr, "got HTTP data\n");
                        break;
                    }

                    case QUICHE_H3_EVENT_FINISHED:
                        break;

                    case QUICHE_H3_EVENT_RESET:
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
    }

    HASH_ITER(hh, conns->h, conn_io, tmp) {
        if (conn_io->file >= 0){
            int size = read(conn_io->file, file_buf, 65535);
            quiche_h3_send_body(conn_io->http3, conn_io->conn,
                                conn_io->stream, file_buf, size, size == 0);
        }

        schedule(conn_io);
        flush_egress(loop, conn_io);

        if (quiche_conn_is_closed(conn_io->conn)) {
            quiche_stats stats;
            quiche_path_stats path_stats;

            quiche_conn_stats(conn_io->conn, &stats);
            quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

            fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                    stats.recv, stats.sent, stats.lost, path_stats.rtt, path_stats.cwnd);

            HASH_DELETE(hh, conns->h, conn_io);

            ev_timer_stop(loop, &conn_io->timer);

            quiche_conn_free(conn_io->conn);
            free(conn_io);
        }
    }

    HASH_ITER(hh, conns_id->h, st, st_tmp) {
        HASH_FIND(hh, conns->h, &st->id, sizeof(int), tmp);
        if (!tmp){
            HASH_DELETE(hh, conns_id->h, st);
        }
    }
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

        fprintf(stderr, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                stats.recv, stats.sent, stats.lost, path_stats.rtt, path_stats.cwnd);

        HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->timer);
        quiche_conn_free(conn_io->conn);
        free(conn_io);

        return;
    }
}

int main(int argc, char *argv[]) {
    const char *host = argv[1];
    const char *port = argv[2];

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *local;
    if (getaddrinfo(host, port, &hints, &local) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(local->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (bind(sock, local->ai_addr, local->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_load_cert_chain_from_pem_file(config, "./cert.crt");
    quiche_config_load_priv_key_from_pem_file(config, "./cert.key");

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
    // quiche_config_set_disable_active_migration(config, true);
    quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);
    quiche_config_set_active_connection_id_limit(config, 5);

    http3_config = quiche_h3_config_new();
    if (http3_config == NULL) {
        fprintf(stderr, "failed to create HTTP/3 config\n");
        return -1;
    }

    struct connections c;
    c.sock = sock;
    c.h = NULL;
    memcpy(&c.local_addr, local->ai_addr, local->ai_addrlen);
    c.local_addr_len = local->ai_addrlen;

    struct connection_ids c_id;
    c_id.h = NULL;

    conns = &c;
    conns_id = &c_id;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = &c;

    ev_loop(loop, 0);

    freeaddrinfo(local);

    quiche_h3_config_free(http3_config);

    quiche_config_free(config);

    return 0;
}
