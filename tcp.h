#pragma once
#include "config.h"
#include <sys/select.h>
#define BUF_SIZE 1024

typedef struct {
    int src_fd;
    config_addr_t src_addr;
    config_addr_t dst_addr;
} tcp_sock_listen_t;

typedef struct tcp_sock_session_t {
    int new_connection;
    int incoming_fd;
    int outgoing_fd;
    char incoming_outgoing_buf[BUF_SIZE];
    int incoming_outgoing_buf_len;
    char outgoing_incoming_buf[BUF_SIZE];
    int outgoing_incoming_buf_len;
    int incoming_outgoing_shutdown;
    int outgoing_incoming_shutdown;
    struct tcp_sock_session_t *prev_session;
    struct tcp_sock_session_t *next_session;
} tcp_sock_session_t;

// Handles connections that originate from TCP and destines to a TCP port
int tcp_init_from_config(config_item_t *config, size_t config_len);
// Builds fd sets that the TCP module concerns about
// returns the maximum fd as found in this module,
// -1 if none
int tcp_build_fd_sets(fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
// The event loop handler for the TCP module
void tcp_ev_loop_handler(fd_set *readfds, fd_set *writefds, fd_set *exceptfds);