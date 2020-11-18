#pragma once
#include "config.h"
#define BUF_SIZE 16384 // 16k, same as kernel (by default)

typedef struct {
    size_t cfg_idx;
    int src_fd;
    config_addr_t src_addr;
    config_addr_t dst_addr;
    config_addr_t *failover_addrs;
    size_t failover_addrs_num;
    size_t failover_cur_idx;
    unsigned long connection_failed_cnt;
} tcp_sock_listen_t;

typedef struct tcp_sock_session_t {
    // The index of the corresponding config item of this session
    size_t cfg_idx;
    // 1 if this session has never yet been put into a poll()
    int new_connection;
    // The fd from the client to yapofw
    int incoming_fd;
    // The fd from yapofw to the target host
    int outgoing_fd;
    // Buffer for the incoming-outgoing direction
    char incoming_outgoing_buf[BUF_SIZE];
    // Length of the used portion of the buffer
    int incoming_outgoing_buf_len;
    // Length of the portion of the buffer that
    // has been written (within incoming_outgoing_buf_len)
    // This is for handling the rare case when write()
    // returns less than the buffer length
    int incoming_outgoing_buf_written;
    // Buffer for the outgoing-incoming direction
    char outgoing_incoming_buf[BUF_SIZE];
    // See the incoming counterpart
    int outgoing_incoming_buf_len;
    // See the incoming counterpart
    int outgoing_incoming_buf_written;
    // 1 if the incoming-outgoing direction has errored
    // or has been shut down
    int incoming_outgoing_shutdown;
    // 1 if the outgoing-incoming direction has errored
    // or has been shut down
    int outgoing_incoming_shutdown;
    // Address of the client
    struct sockaddr client_addr;
    // Address of the target host
    struct sockaddr dst_addr;
    // The previous session in the linked list
    struct tcp_sock_session_t *prev_session;
    // The next session in the linked list
    struct tcp_sock_session_t *next_session;
} tcp_sock_session_t;

// Handles connections that originate from TCP and destines to a TCP port
int tcp_init_from_config(config_item_t *config, size_t config_len);