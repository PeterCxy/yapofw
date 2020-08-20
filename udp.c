#include "udp.h"
#include "loop.h"
#include "stats.h"
#include "util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Temporary variables for formatting
static char ip_str[255];
static char ip_str_1[255];
static char ip_str_2[255];

static udp_sock_listen_t *listen_sockets = NULL;
static size_t listen_sockets_len = 0;

// This is an array of linked lists:
// the array index identifies the corresponding index in the listen_sockets
// of the session's incoming side
// while the linked list is a set of outgoing sessions associated with that
// listening socket
// (we are essentially doing what NAT does for UDP here)
static udp_sock_session_t **sessions = NULL;

void udp_add_session(size_t listen_socket_idx, udp_sock_session_t session) {
    udp_sock_session_t *session_heap = malloc(sizeof(udp_sock_session_t));
    if (session_heap == NULL) return;
    memcpy(session_heap, &session, sizeof(udp_sock_session_t));

    if (sessions[listen_socket_idx] == NULL) {
        sessions[listen_socket_idx] = session_heap;
    } else {
        sessions[listen_socket_idx]->prev_session = session_heap;
        session_heap->next_session = sessions[listen_socket_idx];
        sessions[listen_socket_idx] = session_heap;
    }
}

// Removes the session and returns the original next_session
udp_sock_session_t *udp_remove_session(size_t listen_socket_idx, udp_sock_session_t *session) {
    if (session->prev_session != NULL) {
        session->prev_session->next_session = session->next_session;
    } else {
        sessions[listen_socket_idx] = session->next_session;
    }

    if (session->next_session != NULL) {
        session->next_session->prev_session = session->prev_session;
    }

    udp_sock_session_t *ret = session->next_session;
    free(session);
    return ret;
}

void udp_after_poll() {
    // Since we do not need to worry about dropping packets
    // all sessions share a same pair of temporary buffers
    // if stuff in the buffer cannot be sent immediately,
    // they are simply discarded.
    static char buf[UDP_BUF_SIZE];
    static char buf2[UDP_BUF_SIZE];
    static struct sockaddr in_addr;

    for (size_t i = 0; i < listen_sockets_len; i++) {
        ssize_t in_read_len = 0;
        if (event_loop_fd_revent_is_set(listen_sockets[i].src_fd, POLLIN)) {
            // We can read something from the socket
            socklen_t in_addr_len = sizeof(struct sockaddr);
            in_read_len = recvfrom(listen_sockets[i].src_fd, buf, sizeof(buf), MSG_DONTWAIT,
                            &in_addr, &in_addr_len);
            // Don't need to fail if cannot read, just pretend we have read nothing
            // because we are UDP
            if (in_read_len > 0)
                stats_add_bytes(listen_sockets[i].cfg_idx, in_read_len, STATS_DIRECTION_SRC_DST);
        }

        // We also need to loop over all sessions associated with this socket
        // regardless of whether we read, since those sessions might have something available
        // or they may timeout and need to be removed
        udp_sock_session_t *cur_session = sessions[i];
        int session_found = 0;
        time_t now = time(NULL);
        while (cur_session != NULL) {
            int has_activity = 0;
            if (in_read_len > 0) {
                // The incoming socket has something
                // Check if we are the corresponding session
                if (sockaddr_cmp(&cur_session->client_addr, &in_addr) == 0) {
                    // We are the session!
                    session_found = 1;
                    has_activity = 1;
                    sendto(cur_session->outgoing_fd, buf, in_read_len, MSG_DONTWAIT,
                        &cur_session->dst_addr, sizeof(struct sockaddr));
                    // If we cannot write right now, just drop it
                    // we don't need to care
                }
            }

            if (event_loop_fd_revent_is_set(cur_session->outgoing_fd, POLLIN)) {
                // The other direction
                // use the other buffer in case other session might need the
                // original buffer
                ssize_t read_len = recvfrom(cur_session->outgoing_fd, buf2, sizeof(buf2), MSG_DONTWAIT,
                                    NULL, NULL);
                if (read_len > 0) {
                    has_activity = 1;
                    sendto(listen_sockets[i].src_fd, buf2, read_len, MSG_DONTWAIT,
                        &cur_session->client_addr, sizeof(struct sockaddr));
                    stats_add_bytes(listen_sockets[i].cfg_idx, read_len, STATS_DIRECTION_DST_SRC);
                }
            }

            if (has_activity) {
                cur_session->last_activity = now;
            }

            if (now - cur_session->last_activity >= UDP_TIMEOUT) {
                printf("[UDP] Session timeout, tearing down (%s:%d -> %s:%d)\n",
                    get_ip_str(&cur_session->client_addr, ip_str, 255), get_ip_port(&cur_session->client_addr),
                    config_addr_to_str(&listen_sockets[i].dst_addr, ip_str_1, 255), listen_sockets[i].dst_addr.port);
                close(cur_session->outgoing_fd);
                event_loop_remove_fd(cur_session->outgoing_fd);
                cur_session = udp_remove_session(i, cur_session);
            } else {
                cur_session = cur_session->next_session;
            }
        }

        if (in_read_len > 0 && session_found == 0) {
            printf("[UDP] New session from %s:%d on %s:%d, target: %s:%d\n",
                get_ip_str(&in_addr, ip_str, 255), get_ip_port(&in_addr),
                config_addr_to_str(&listen_sockets[i].src_addr, ip_str_1, 255), listen_sockets[i].src_addr.port,
                config_addr_to_str(&listen_sockets[i].dst_addr, ip_str_2, 255), listen_sockets[i].dst_addr.port);

            // We need to create a new session
            size_t sockaddr_len = 0;
            struct sockaddr *address =
                config_addr_to_sockaddr(&listen_sockets[i].dst_addr, &sockaddr_len);
            if (address == NULL) {
                printf("Cannot properly convert UDP socket address\n");
                continue;
            }

            int fd = socket(listen_sockets[i].dst_addr.af, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            if (fd < 0) {
                printf("Cannot create UDP socket\n");
                continue;
            }

            // Write whatever is available to the destination right now
            sendto(fd, buf, in_read_len, MSG_DONTWAIT, address, sizeof(struct sockaddr));

            udp_sock_session_t session;
            memset(&session, 0, sizeof(session));
            session.client_addr = in_addr;
            session.dst_addr = *address;
            session.last_activity = now;
            session.outgoing_fd = fd;

            event_loop_add_fd(fd, POLLIN);

            udp_add_session(i, session);

            free(address);
        }
    }
}

int udp_init_from_config(config_item_t *config, size_t config_len) {
    listen_sockets = malloc(sizeof(udp_sock_listen_t) * config_len);
    sessions = malloc(sizeof(udp_sock_session_t *) * config_len);
    if (listen_sockets == NULL || sessions == NULL) return -1;
    memset(listen_sockets, 0, sizeof(udp_sock_listen_t) * config_len);
    memset(sessions, 0, sizeof(udp_sock_session_t *) * config_len);

    for (size_t i = 0; i < config_len; i++) {
        if (config[i].src_proto != UDP && config[i].dst_proto != UDP)
            continue;
        int fd = socket(config[i].src_addr.af, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            printf("Cannot create UDP socket: %s\n", strerror(errno));
            return -1;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
            printf("setsockopt failed with %s\n", strerror(errno));
            return -1;
        }

        char *address_str = config_addr_to_str(&config[i].src_addr, ip_str, 255);
        printf("[UDP] Listening on %s:%d\n", address_str, config[i].src_addr.port);

        size_t sockaddr_len = 0;
        struct sockaddr *address =
            config_addr_to_sockaddr(&config[i].src_addr, &sockaddr_len);
        if (address == NULL) {
            printf("Cannot properly convert UDP socket address\n");
            return -1;
        }

        if (bind(fd, address, sockaddr_len) < 0) {
            printf("Cannot bind to %s:%d\n", address_str, config[i].src_addr.port);
            return -1;
        }

        listen_sockets[listen_sockets_len].cfg_idx = i;
        listen_sockets[listen_sockets_len].src_fd = fd;
        listen_sockets[listen_sockets_len].src_addr = config[i].src_addr;
        listen_sockets[listen_sockets_len].dst_addr = config[i].dst_addr;
        listen_sockets_len++;

        // Register the fd to monitor for reads
        event_loop_add_fd(fd, POLLIN);

        free(address);
    }

    // Register event loop hooks
    event_loop_register_hook_after_poll(&udp_after_poll);

    return 0;
}