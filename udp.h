#pragma once
#include "config.h"
#include "time.h"
#define UDP_TIMEOUT 60
#define UDP_BUF_SIZE 1500 // Ethernet MTU

typedef struct {
    size_t cfg_idx;
    int src_fd;
    config_addr_t src_addr;
    config_addr_t dst_addr;
} udp_sock_listen_t;

typedef struct udp_sock_session_t {
    // Timestamp of last activity, used for timeouts
    time_t last_activity;
    // The outgoing socket fd
    int outgoing_fd;
    // Address of the client
    struct sockaddr client_addr;
    // Address of the target host
    struct sockaddr dst_addr;
    // The previous session in the linked list
    struct udp_sock_session_t *prev_session;
    // The next session in the linked list
    struct udp_sock_session_t *next_session;
} udp_sock_session_t;

int udp_init_from_config(config_item_t *config, size_t config_len);