#include "tcp.h"
#include "loop.h"
#include "stats.h"
#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

char ip_str[255];

tcp_sock_listen_t *listen_sockets = NULL;
size_t listen_sockets_len = 0;

tcp_sock_session_t *sessions = NULL;

void tcp_session_add(tcp_sock_session_t session) {
    tcp_sock_session_t *session_heap = malloc(sizeof(tcp_sock_session_t));
    if (session_heap == NULL) return;
    memcpy(session_heap, &session, sizeof(tcp_sock_session_t));
    if (sessions == NULL) {
        sessions = session_heap;
    } else {
        // Add the session to the head because it's faster
        session_heap->next_session = sessions;
        sessions->prev_session = session_heap;
        sessions = session_heap;
    }
}

tcp_sock_session_t *tcp_session_remove(tcp_sock_session_t *session) {
    // Link the previous session to next or NULL (removing this from the chain)
    if (session->prev_session != NULL) {
        session->prev_session->next_session = session->next_session;
    } else {
        sessions = session->next_session;
    }

    // Also remove reference from the next session in the chain
    if (session->next_session != NULL) {
        session->next_session->prev_session = session->prev_session;
    }

    tcp_sock_session_t *ret = session->next_session;
    free(session);
    return ret;
}

void tcp_handle_accept() {
    // Loop over all listening sockets to see if we need to accept any new connection
    for (int i = 0; i < listen_sockets_len; i++) {
        if (!event_loop_fd_revent_is_set(listen_sockets[i].src_fd, POLLIN)) continue;
        // New connection!
        struct sockaddr client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd;
        if ((client_fd = accept(listen_sockets[i].src_fd, &client_addr, &client_addr_len)) < 0) {
            printf("[TCP] Error accepting incoming connection: %s\n", strerror(errno));
            continue;
        }

        if (fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
            printf("[TCP] Error setting O_NONBLOCK on incoming connection: %s\n", strerror(errno));
            continue;
        }

        printf("[TCP] New connection from %s:%d on %s:%d, target: %s:%d\n",
            get_ip_str(&client_addr, ip_str, 255), get_ip_port(&client_addr),
            config_addr_to_str(&listen_sockets[i].src_addr, ip_str, 255), listen_sockets[i].src_addr.port,
            config_addr_to_str(&listen_sockets[i].dst_addr, ip_str, 255), listen_sockets[i].dst_addr.port);

        // Create connection to target
        int server_fd = socket(listen_sockets[i].dst_addr.af, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (server_fd < 0) {
            printf("[TCP] Unable to create connection to %s:%d, error: %s\n",
                config_addr_to_str(&listen_sockets[i].dst_addr, ip_str, 255), listen_sockets[i].dst_addr.port,
                strerror(errno));
            close(client_fd);
            continue;
        }

        size_t sockaddr_len = 0;
        struct sockaddr *address =
            config_addr_to_sockaddr(&listen_sockets[i].dst_addr, &sockaddr_len);
        if (address == NULL) {
            printf("Cannot properly convert TCP socket address\n");
            close(server_fd);
            close(client_fd);
            continue;
        }

        if (connect(server_fd, address, sockaddr_len) < 0 && errno != EINPROGRESS) {
            printf("[TCP] Unable to connect to %s:%d, error: %s\n",
                config_addr_to_str(&listen_sockets[i].dst_addr, ip_str, 255), listen_sockets[i].dst_addr.port,
                strerror(errno));
            close(client_fd);
            close(server_fd);
            continue;
        }

        // Add the session to session list
        tcp_sock_session_t session;
        memset(&session, 0, sizeof(tcp_sock_session_t));
        session.cfg_idx = listen_sockets[i].cfg_idx;
        session.incoming_fd = client_fd;
        session.outgoing_fd = server_fd;
        session.client_addr = client_addr;
        session.dst_addr = *address;
        session.new_connection = 1;
        tcp_session_add(session);

        // Also register for monitoring
        event_loop_add_fd(client_fd, POLLIN | POLLOUT);
        event_loop_add_fd(server_fd, POLLIN | POLLOUT);

        // Free the address object -- it's no longer needed
        free(address);
    }
}

void tcp_do_forward(int *src_fd, int *dst_fd,
        char *buf, int *buf_len,
        int *buf_written, int *shutdown_src_dst,
        struct sockaddr *src_addr, struct sockaddr *dst_addr,
        size_t stats_cfg_idx, int stats_direction) {
    if (event_loop_fd_revent_is_set(*src_fd, POLLIN) && *buf_len < BUF_SIZE) {
        // As long as the read buffer is not full, continue reading
        ssize_t len = read(*src_fd, &buf[*buf_len], BUF_SIZE - *buf_len);
        if (len < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("[TCP] Unable to read from %s:%d: %s\n",
                    get_ip_str(src_addr, ip_str, 255), get_ip_port(src_addr),
                    strerror(errno));
                shutdown(*dst_fd, SHUT_WR);
                *shutdown_src_dst = 1;
            }
        } else if (len == 0) {
            // EOF
            shutdown(*dst_fd, SHUT_WR);
            *shutdown_src_dst = 1;
        } else {
            *buf_len += len;
            // Hook into the stats module
            // Remember to call this whenever we receive any data
            stats_add_bytes(stats_cfg_idx, len, stats_direction);
        }
    }

    if (*buf_len != 0) {
        ssize_t written = write(*dst_fd, &buf[*buf_written], *buf_len - *buf_written);
        if (written < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("[TCP] Unable to write to %s:%d: %s\n",
                    get_ip_str(dst_addr, ip_str, 255), get_ip_port(dst_addr),
                    strerror(errno));
                shutdown(*src_fd, SHUT_RD);
                *shutdown_src_dst = 1;
                *buf_written = 0;
                *buf_len = 0;
            }
        } else if (written < *buf_len - *buf_written) {
            // We have written less than the full length
            // Record where we have written to and continue next time
            *buf_written += written;
        } else {
            *buf_written = 0;
            *buf_len = 0;
        }
    }

    if (*buf_len == BUF_SIZE) {
        // Stop polling for reads from src, but keep polling for writes to dst
        event_loop_clear_fd_events(*src_fd, POLLIN);
        event_loop_set_fd_events(*dst_fd, POLLOUT);
    } else if (*buf_len == 0) {
        // Stop polling for writes to dst, but keep polling reads from src
        event_loop_clear_fd_events(*dst_fd, POLLOUT);
        event_loop_set_fd_events(*src_fd, POLLIN);
    } else {
        // When we have some buffer and not full, make sure we poll
        // for both reads from src and writes to dst
        event_loop_set_fd_events(*src_fd, POLLIN);
        event_loop_set_fd_events(*dst_fd, POLLOUT);
    }
}

void tcp_handle_forward() {
    tcp_sock_session_t *cur_session = sessions;
    while (cur_session != NULL) {
        if (cur_session->new_connection
                && event_loop_fd_revent_is_set(cur_session->outgoing_fd, POLLIN)) {
            // The new connection has been set up (or failed)
            int err = 0;
            unsigned int optlen = sizeof(int);
            getsockopt(cur_session->outgoing_fd, SOL_SOCKET, SO_ERROR, &err, &optlen);
            if (err != 0) {
                printf("[TCP] %s:%d -> %s:%d failed: %s\n",
                    get_ip_str(&cur_session->client_addr, ip_str, 255), get_ip_port(&cur_session->client_addr),
                    get_ip_str(&cur_session->dst_addr, ip_str, 255), get_ip_port(&cur_session->dst_addr),
                    strerror(err));
                shutdown(cur_session->incoming_fd, SHUT_RDWR);
                shutdown(cur_session->outgoing_fd, SHUT_RDWR);
                cur_session->incoming_outgoing_shutdown = 1;
                cur_session->outgoing_incoming_shutdown = 1;
            }
            cur_session->new_connection = 0;
        }

        // client -> remote
        tcp_do_forward(&cur_session->incoming_fd, &cur_session->outgoing_fd,
            cur_session->incoming_outgoing_buf, &cur_session->incoming_outgoing_buf_len,
            &cur_session->incoming_outgoing_buf_written, &cur_session->incoming_outgoing_shutdown,
            &cur_session->client_addr, &cur_session->dst_addr,
            cur_session->cfg_idx, STATS_DIRECTION_SRC_DST);
        // remote -> client
        tcp_do_forward(&cur_session->outgoing_fd, &cur_session->incoming_fd,
            cur_session->outgoing_incoming_buf, &cur_session->outgoing_incoming_buf_len,
            &cur_session->outgoing_incoming_buf_written, &cur_session->outgoing_incoming_shutdown,
            &cur_session->dst_addr, &cur_session->client_addr,
            cur_session->cfg_idx, STATS_DIRECTION_DST_SRC);

        // Destroy the session if both sides are dead
        if (cur_session->incoming_outgoing_shutdown
                    && cur_session->outgoing_incoming_shutdown) {
            printf("[TCP] Tearing down connection %s:%d -> %s:%d\n",
                get_ip_str(&cur_session->client_addr, ip_str, 255), get_ip_port(&cur_session->client_addr),
                get_ip_str(&cur_session->dst_addr, ip_str, 255), get_ip_port(&cur_session->dst_addr));
            close(cur_session->incoming_fd);
            close(cur_session->outgoing_fd);
            // Also unregister from ev loop
            event_loop_remove_fd(cur_session->incoming_fd);
            event_loop_remove_fd(cur_session->outgoing_fd);
            // Remove session
            cur_session = tcp_session_remove(cur_session);
        } else {
            cur_session = cur_session->next_session;
        }
    }
}

void tcp_after_poll() {
    // Handle new connections from the listening socket
    tcp_handle_accept();
    // Handle forwarding in single tcp connections
    tcp_handle_forward();
}

int tcp_init_from_config(config_item_t *config, size_t config_len) {
    // We always over-allocate to the total number of config lines
    // it should be fine as we don't expect too many lines of configuration
    listen_sockets = malloc(sizeof(tcp_sock_listen_t) * config_len);
    if (listen_sockets == NULL) return -1;
    memset(listen_sockets, 0, sizeof(tcp_sock_listen_t) * config_len);

    for (size_t i = 0; i < config_len; i++) {
        if (config[i].src_proto != TCP || config[i].dst_proto != TCP)
            continue;
        // Create listening socket
        int fd = socket(config[i].src_addr.af, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            printf("Cannot create TCP socket\n");
            return -1;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
            printf("setsockopt failed with %s\n", strerror(errno));
            return -1;
        }

        char *address_str = config_addr_to_str(&config[i].src_addr, ip_str, 255);
        printf("[TCP] Listening on %s:%d\n", address_str, config[i].src_addr.port);

        size_t sockaddr_len = 0;
        struct sockaddr *address =
            config_addr_to_sockaddr(&config[i].src_addr, &sockaddr_len);
        if (address == NULL) {
            printf("Cannot properly convert TCP socket address\n");
            return -1;
        }

        if (bind(fd, address, sockaddr_len) < 0) {
            printf("Cannot bind to %s:%d\n", address_str, config[i].src_addr.port);
            return -1;
        }

        if (listen(fd, 255) < 0) {
            printf("Cannot listen on %s:%d\n", address_str, config[i].src_addr.port);
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
    
    // Register handlers
    event_loop_register_hook_after_poll(&tcp_after_poll);

    return 0;
}