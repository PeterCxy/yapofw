#pragma once
#include "config.h"
#define BUF_SIZE 16384 // 16k, same as kernel (by default)

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
    int incoming_outgoing_buf_written;
    char outgoing_incoming_buf[BUF_SIZE];
    int outgoing_incoming_buf_len;
    int outgoing_incoming_buf_written;
    int incoming_outgoing_shutdown;
    int outgoing_incoming_shutdown;
    struct sockaddr client_addr;
    config_addr_t dst_addr;
    struct tcp_sock_session_t *prev_session;
    struct tcp_sock_session_t *next_session;
} tcp_sock_session_t;

// Handles connections that originate from TCP and destines to a TCP port
int tcp_init_from_config(config_item_t *config, size_t config_len);